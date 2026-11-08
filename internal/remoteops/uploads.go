// Package remoteops runs the agent's remote operations: collect_file,
// run_command, file_operation (incl. cross-device copy / move) and
// interactive shells (open_shell + ShellSession). Each is a signed, audited
// agent_commands row first; uploads, transfers and shell sessions are tracked
// in their own tables (migration 0020).
package remoteops

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	aegisonev1 "aegis-one/gen/aegisone/v1"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Upload caps per command (the agent's own defaults, with room for ZIP
// overhead on pack).
const (
	collectDefaultTotal = 500 << 20
	collectHardTotal    = 2 << 30
	runOutputMax        = 1 << 30
	packMax             = 600 << 20
)

// Uploads stores files agents stream with UploadContent.
type Uploads struct {
	pool *pgxpool.Pool
	dir  string // content dir; files go under <dir>/uploads/
	log  *slog.Logger
}

func NewUploads(pool *pgxpool.Pool, contentDir string, log *slog.Logger) *Uploads {
	return &Uploads{pool: pool, dir: contentDir, log: log}
}

// ErrUploadRefused is a request the agent gets an UploadAck.error for.
type ErrUploadRefused struct{ msg string }

func (e *ErrUploadRefused) Error() string { return e.msg }

// Receive reads one UploadContent stream from an identified agent and
// returns the ack to send. The first chunk names the command (action_id),
// which must be an open command of this agent that is allowed to upload; the
// last chunk carries the whole file's SHA-256, which must match.
func (u *Uploads) Receive(ctx context.Context, recv func() (*aegisonev1.UploadChunk, error), deviceUUID, agentUUID string) *aegisonev1.UploadAck {
	first, err := recv()
	if err != nil {
		return &aegisonev1.UploadAck{Error: "no chunks received"}
	}
	commandID, name := strings.TrimSpace(first.GetActionId()), sanitizeName(first.GetName())
	limit, err := u.allowance(ctx, commandID, agentUUID)
	if err != nil {
		var refused *ErrUploadRefused
		if errors.As(err, &refused) {
			u.log.Warn("upload refused", "device_uuid", deviceUUID, "command_id", commandID, "reason", refused.msg)
			return &aegisonev1.UploadAck{Error: refused.msg}
		}
		u.log.Error("upload: check command", "error", err.Error())
		return &aegisonev1.UploadAck{Error: "server error"}
	}

	relDir := filepath.ToSlash(filepath.Join("uploads", deviceUUID, commandID))
	absDir := filepath.Join(u.dir, filepath.FromSlash(relDir))
	if err := os.MkdirAll(absDir, 0o750); err != nil {
		u.log.Error("upload: mkdir", "error", err.Error())
		return &aegisonev1.UploadAck{Error: "server error"}
	}
	tmp, err := os.CreateTemp(absDir, ".upload-*.tmp")
	if err != nil {
		u.log.Error("upload: temp file", "error", err.Error())
		return &aegisonev1.UploadAck{Error: "server error"}
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name()) // no-op once renamed
	}()
	h := sha256.New()
	var n int64
	sum := ""
	chunk := first
	for {
		if d := chunk.GetData(); len(d) > 0 {
			n += int64(len(d))
			if n > limit {
				return &aegisonev1.UploadAck{ReceivedBytes: n, Error: fmt.Sprintf("upload exceeds the %d-byte limit for this command", limit)}
			}
			if _, err := tmp.Write(d); err != nil {
				u.log.Error("upload: write", "error", err.Error())
				return &aegisonev1.UploadAck{Error: "server error"}
			}
			h.Write(d)
		}
		if s := chunk.GetSha256Full(); s != "" {
			sum = strings.ToLower(s)
		}
		next, err := recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return &aegisonev1.UploadAck{ReceivedBytes: n, Error: "stream error"}
		}
		chunk = next
	}
	got := hex.EncodeToString(h.Sum(nil))
	if sum == "" || sum != got {
		u.log.Warn("upload integrity failed", "device_uuid", deviceUUID, "command_id", commandID, "name", name)
		return &aegisonev1.UploadAck{ReceivedBytes: n, IntegrityOk: false, Error: "sha256 mismatch (or missing) on upload"}
	}
	if err := tmp.Close(); err != nil {
		return &aegisonev1.UploadAck{Error: "server error"}
	}
	final, rel := uniquePath(absDir, relDir, name)
	if err := os.Rename(tmp.Name(), final); err != nil {
		u.log.Error("upload: store", "error", err.Error())
		return &aegisonev1.UploadAck{Error: "server error"}
	}
	if _, err := u.pool.Exec(ctx, `
		INSERT INTO agent_uploads (device_id, agent_id, command_id, name, stored_name, size_bytes, sha256)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, deviceUUID, agentUUID, commandID, name, rel, n, got); err != nil {
		os.Remove(final)
		u.log.Error("upload: record", "error", err.Error())
		return &aegisonev1.UploadAck{Error: "server error"}
	}
	u.log.Info("upload stored", "device_uuid", deviceUUID, "command_id", commandID, "name", name, "bytes", n, "sha256", got)
	return &aegisonev1.UploadAck{StoredPath: rel, ReceivedBytes: n, IntegrityOk: true}
}

// allowance returns how many bytes this upload may have, after checking that
// commandID is an open upload-capable command of this agent.
func (u *Uploads) allowance(ctx context.Context, commandID, agentUUID string) (int64, error) {
	if len(commandID) != 36 {
		return 0, &ErrUploadRefused{"action_id must be the command id"}
	}
	var cmdType, status string
	var payload []byte
	err := u.pool.QueryRow(ctx, `SELECT command_type, status, payload FROM agent_commands WHERE id::text = $1 AND agent_id = $2`,
		commandID, agentUUID).Scan(&cmdType, &status, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, &ErrUploadRefused{"no such command for this agent"}
	}
	if err != nil {
		return 0, err
	}
	if status != "queued" && status != "dispatched" && status != "acknowledged" {
		return 0, &ErrUploadRefused{"command is already finished (" + status + ")"}
	}
	var p struct {
		UploadAs      string `json:"upload_as"`
		Operation     string `json:"operation"`
		MaxTotalBytes int64  `json:"max_total_bytes"`
	}
	_ = json.Unmarshal(payload, &p)
	var used int64
	if err := u.pool.QueryRow(ctx, `SELECT coalesce(sum(size_bytes), 0) FROM agent_uploads WHERE command_id::text = $1`, commandID).Scan(&used); err != nil {
		return 0, err
	}
	var limit int64
	switch {
	case cmdType == "collect_file":
		limit = collectDefaultTotal
		if p.MaxTotalBytes > 0 {
			limit = min(p.MaxTotalBytes, collectHardTotal)
		}
	case cmdType == "run_command" && p.UploadAs != "":
		limit = runOutputMax
	case cmdType == "file_operation" && p.Operation == "pack":
		limit = packMax
	default:
		return 0, &ErrUploadRefused{cmdType + " does not upload files"}
	}
	if used >= limit {
		return 0, &ErrUploadRefused{"this command's upload quota is used up"}
	}
	return limit - used, nil
}

// sanitizeName keeps a plain file name: the base name, safe characters only.
func sanitizeName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, `\`, "/"))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		out = "file"
	}
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return out
}

// uniquePath picks a free name in dir: name, name-2, name-3, ...
func uniquePath(absDir, relDir, name string) (abs, rel string) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		candidate := name
		if i > 1 {
			candidate = fmt.Sprintf("%s-%d%s", stem, i, ext)
		}
		abs = filepath.Join(absDir, candidate)
		if _, err := os.Lstat(abs); errors.Is(err, os.ErrNotExist) {
			return abs, relDir + "/" + candidate
		}
		if i > 1000 {
			var r [6]byte
			rand.Read(r[:])
			candidate = stem + "-" + hex.EncodeToString(r[:]) + ext
			return filepath.Join(absDir, candidate), relDir + "/" + candidate
		}
	}
}

// Upload is one stored file, for the API.
type Upload struct {
	ID        string `json:"upload_id"`
	CommandID string `json:"command_id"`
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	CreatedAt string `json:"created_at"`
	stored    string
}

func (u *Uploads) list(ctx context.Context, commandID string) ([]Upload, error) {
	rows, err := u.pool.Query(ctx, `
		SELECT up.id::text, up.command_id::text, d.agent_reported_id, up.name, up.size_bytes, up.sha256,
		       to_char(up.created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), up.stored_name
		FROM agent_uploads up JOIN devices d ON d.id = up.device_id
		WHERE up.command_id::text = $1 ORDER BY up.created_at`, commandID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Upload{}
	for rows.Next() {
		var x Upload
		if err := rows.Scan(&x.ID, &x.CommandID, &x.DeviceID, &x.Name, &x.SizeBytes, &x.SHA256, &x.CreatedAt, &x.stored); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (u *Uploads) get(ctx context.Context, id string) (*Upload, error) {
	var x Upload
	err := u.pool.QueryRow(ctx, `
		SELECT up.id::text, up.command_id::text, d.agent_reported_id, up.name, up.size_bytes, up.sha256, '', up.stored_name
		FROM agent_uploads up JOIN devices d ON d.id = up.device_id WHERE up.id::text = $1`, id).
		Scan(&x.ID, &x.CommandID, &x.DeviceID, &x.Name, &x.SizeBytes, &x.SHA256, &x.CreatedAt, &x.stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &x, err
}

// path is the upload's file on disk.
func (u *Uploads) path(x *Upload) string {
	return filepath.Join(u.dir, filepath.FromSlash(x.stored))
}
