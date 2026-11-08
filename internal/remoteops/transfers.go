package remoteops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"aegis-one/internal/commands"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxTransferTargets = 100
	// transferStepTimeout fails a transfer whose current step (a device being
	// offline, or no answer) takes longer than this.
	transferStepTimeout = time.Hour
)

// Transfers copies or moves files from one endpoint to others (see the
// file_transfers table, migration 0020).
type Transfers struct {
	pool    *pgxpool.Pool
	uploads *Uploads
	sender  *commands.Sender
	log     *slog.Logger
	wake    chan struct{}
}

func NewTransfers(pool *pgxpool.Pool, uploads *Uploads, sender *commands.Sender, log *slog.Logger) *Transfers {
	return &Transfers{pool: pool, uploads: uploads, sender: sender, log: log, wake: make(chan struct{}, 1)}
}

// fileSpec is the agent's file_operation/v1 JSON payload.
type fileSpec struct {
	Version        int             `json:"version"`
	Operation      string          `json:"operation"`
	Source         string          `json:"source,omitempty"`
	Destination    string          `json:"destination,omitempty"`
	WorkingDir     string          `json:"working_dir,omitempty"`
	Recursive      bool            `json:"recursive,omitempty"`
	Overwrite      bool            `json:"overwrite,omitempty"`
	DestinationDir bool            `json:"destination_dir,omitempty"`
	MaxBytes       int64           `json:"max_bytes,omitempty"`
	MaxFiles       int             `json:"max_files,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"`
	ContentID      string          `json:"content_id,omitempty"`
	SHA256         string          `json:"sha256,omitempty"`
	Entries        json.RawMessage `json:"entries,omitempty"`
	Content        []byte          `json:"content,omitempty"`
	Append         bool            `json:"append,omitempty"`
}

// fileResult is the agent's file_operation result (ActionStatus.detail).
type fileResult struct {
	Files      int             `json:"files"`
	Bytes      int64           `json:"bytes"`
	Entries    json.RawMessage `json:"entries,omitempty"`
	StoredPath string          `json:"stored_path,omitempty"`
	SHA256     string          `json:"sha256,omitempty"`
}

// TransferRequest starts a copy / move.
type TransferRequest struct {
	SourceDeviceID string   `json:"source_device_id"`
	SourcePath     string   `json:"source_path"`
	Recursive      bool     `json:"recursive"`
	DeviceIDs      []string `json:"destination_device_ids"`
	Destination    string   `json:"destination"` // folder on each destination
	Overwrite      bool     `json:"overwrite"`
	Move           bool     `json:"move"`
}

func (t *Transfers) Create(ctx context.Context, r TransferRequest, clientID, clientName string) (string, error) {
	r.SourcePath, r.Destination = strings.TrimSpace(r.SourcePath), strings.TrimSpace(r.Destination)
	if err := checkPath("source_path", r.SourcePath); err != nil {
		return "", err
	}
	if err := checkPath("destination", r.Destination); err != nil {
		return "", err
	}
	targets := dedupe(r.DeviceIDs)
	if len(targets) == 0 || len(targets) > maxTransferTargets {
		return "", userErr("destination_device_ids: 1..%d devices", maxTransferTargets)
	}
	ids := append([]string{r.SourceDeviceID}, targets...)
	uuids := map[string]string{}
	rows, err := t.pool.Query(ctx, `
		SELECT d.agent_reported_id, d.id::text FROM devices d JOIN agents a ON a.device_id = d.id AND a.revoked_at IS NULL
		WHERE d.agent_reported_id = ANY($1)`, ids)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var rid, id string
		if err := rows.Scan(&rid, &id); err != nil {
			rows.Close()
			return "", err
		}
		uuids[rid] = id
	}
	rows.Close()
	for _, id := range ids {
		if uuids[id] == "" {
			return "", userErr("unknown device_id %q", id)
		}
	}
	if r.Move {
		for _, id := range targets {
			if id == r.SourceDeviceID {
				return "", userErr("a move can't target its own source device")
			}
		}
	}
	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO file_transfers (source_device_id, source_path, recursive, destination, overwrite, is_move, created_by_api_client_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id::text`,
		uuids[r.SourceDeviceID], r.SourcePath, r.Recursive, r.Destination, r.Overwrite, r.Move, clientID).Scan(&id); err != nil {
		return "", err
	}
	for _, dev := range targets {
		if _, err := tx.Exec(ctx, `INSERT INTO file_transfer_targets (transfer_id, device_id) VALUES ($1, $2)`, id, uuids[dev]); err != nil {
			return "", err
		}
	}
	details, _ := json.Marshal(map[string]any{"transfer_id": id, "source_device_id": r.SourceDeviceID, "source_path": r.SourcePath,
		"recursive": r.Recursive, "destination_device_ids": targets, "destination": r.Destination, "overwrite": r.Overwrite, "move": r.Move})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', $1, $2, 'files.transfer.create', 'file_transfer', $3, $4::jsonb)`,
		clientID, clientName, id, string(details)); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	select {
	case t.wake <- struct{}{}:
	default:
	}
	return id, nil
}

// Run advances transfers until ctx ends.
func (t *Transfers) Run(ctx context.Context) {
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	for {
		if err := t.advanceAll(ctx); err != nil && ctx.Err() == nil {
			t.log.Warn("file transfers: advance", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		case <-t.wake:
		}
	}
}

type transfer struct {
	id, status, sourceDevice, sourcePath, destination string
	recursive, overwrite, move                        bool
	packCmd, removeCmd, uploadID, archiveSHA          *string
	entries                                           []byte
	clientID                                          *string
	updatedAt                                         time.Time
}

func (t *Transfers) advanceAll(ctx context.Context) error {
	rows, err := t.pool.Query(ctx, `
		SELECT f.id::text, f.status, d.agent_reported_id, f.source_path, f.destination, f.recursive, f.overwrite, f.is_move,
		       f.pack_command_id::text, f.remove_command_id::text, f.upload_id::text, f.archive_sha256, f.entries,
		       f.created_by_api_client_id::text, f.updated_at
		FROM file_transfers f JOIN devices d ON d.id = f.source_device_id
		WHERE f.status NOT IN ('succeeded', 'failed') ORDER BY f.created_at LIMIT 200`)
	if err != nil {
		return err
	}
	var list []transfer
	for rows.Next() {
		var x transfer
		if err := rows.Scan(&x.id, &x.status, &x.sourceDevice, &x.sourcePath, &x.destination, &x.recursive, &x.overwrite, &x.move,
			&x.packCmd, &x.removeCmd, &x.uploadID, &x.archiveSHA, &x.entries, &x.clientID, &x.updatedAt); err != nil {
			rows.Close()
			return err
		}
		list = append(list, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range list {
		var err error
		switch x.status {
		case "packing":
			err = t.pack(ctx, x)
		case "distributing":
			err = t.distribute(ctx, x)
		case "removing_source":
			err = t.removeSource(ctx, x)
		}
		if err != nil {
			t.log.Warn("file transfer: advance", "transfer_id", x.id, "error", err.Error())
		}
	}
	return nil
}

// commandState returns a command's status and its ActionStatus reason/detail.
func (t *Transfers) commandState(ctx context.Context, id string) (status, reason, detail string, err error) {
	err = t.pool.QueryRow(ctx, `
		SELECT status, coalesce(result->>'reason', result->>'message', result->>'error', ''), coalesce(result->>'detail', '')
		FROM agent_commands WHERE id::text = $1`, id).Scan(&status, &reason, &detail)
	return
}

func terminal(status string) bool {
	return status == "succeeded" || status == "failed" || status == "rejected_signature" || status == "expired"
}

func (t *Transfers) send(ctx context.Context, deviceID, clientID string, spec fileSpec, audit map[string]any) (commands.Sent, error) {
	wire, err := json.Marshal(spec)
	if err != nil {
		return commands.Sent{}, err
	}
	return t.sender.Send(ctx, commands.SendRequest{DeviceID: deviceID, Type: "file_operation", Wire: wire, Audit: audit,
		ClientID: clientID, ClientName: "file transfer", Actor: "file_transfer"})
}

func (t *Transfers) pack(ctx context.Context, x transfer) error {
	if x.packCmd == nil {
		if time.Since(x.updatedAt) > transferStepTimeout {
			return t.fail(ctx, x, "the source device was not online to pack the files")
		}
		sent, err := t.send(ctx, x.sourceDevice, deref(x.clientID),
			fileSpec{Version: 1, Operation: "pack", Source: x.sourcePath, Recursive: x.recursive},
			map[string]any{"operation": "pack", "source": x.sourcePath, "recursive": x.recursive, "transfer_id": x.id})
		if err != nil {
			return err
		}
		switch sent.Status {
		case "dispatched":
			_, err = t.pool.Exec(ctx, `UPDATE file_transfers SET pack_command_id = $2, updated_at = now() WHERE id = $1`, x.id, sent.CommandID)
			return err
		case "offline":
			return nil
		default:
			return t.fail(ctx, x, "could not send pack to the source: "+sent.Status+" "+sent.Error)
		}
	}
	st, reason, detail, err := t.commandState(ctx, *x.packCmd)
	if err != nil {
		return err
	}
	if !terminal(st) {
		if time.Since(x.updatedAt) > transferStepTimeout {
			return t.fail(ctx, x, "no answer to pack from the source")
		}
		return nil
	}
	if st != "succeeded" {
		return t.fail(ctx, x, "pack on the source failed: "+reason)
	}
	var res fileResult
	if err := json.Unmarshal([]byte(detail), &res); err != nil || len(res.SHA256) != 64 {
		return t.fail(ctx, x, "pack result has no archive digest")
	}
	// The uploaded archive must be the one the agent says it packed.
	var uploadID, uploadSHA string
	err = t.pool.QueryRow(ctx, `SELECT id::text, sha256 FROM agent_uploads WHERE command_id::text = $1 ORDER BY created_at DESC LIMIT 1`,
		*x.packCmd).Scan(&uploadID, &uploadSHA)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !strings.EqualFold(uploadSHA, res.SHA256)) {
		return t.fail(ctx, x, "the uploaded archive does not match the pack result")
	}
	if err != nil {
		return err
	}
	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, `
		UPDATE file_transfers SET status = 'distributing', upload_id = $2, archive_sha256 = $3, entries = $4::jsonb, updated_at = now()
		WHERE id = $1`, x.id, uploadID, strings.ToLower(res.SHA256), string(orEmptyArray(res.Entries))); err != nil {
		return err
	}
	// One random content id per destination: FetchContent "nsh-file" serves
	// the archive only to that device.
	trows, err := tx.Query(ctx, `SELECT device_id::text FROM file_transfer_targets WHERE transfer_id = $1`, x.id)
	if err != nil {
		return err
	}
	var devs []string
	for trows.Next() {
		var d string
		trows.Scan(&d) //nolint:errcheck
		devs = append(devs, d)
	}
	trows.Close()
	for _, d := range devs {
		var r [24]byte
		if _, err := rand.Read(r[:]); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE file_transfer_targets SET content_id = $3, updated_at = now() WHERE transfer_id = $1 AND device_id = $2`,
			x.id, d, hex.EncodeToString(r[:])); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (t *Transfers) distribute(ctx context.Context, x transfer) error {
	rows, err := t.pool.Query(ctx, `
		SELECT tt.device_id::text, d.agent_reported_id, tt.status, tt.content_id, tt.command_id::text, tt.updated_at
		FROM file_transfer_targets tt JOIN devices d ON d.id = tt.device_id WHERE tt.transfer_id = $1`, x.id)
	if err != nil {
		return err
	}
	type target struct {
		uuid, deviceID, status, contentID string
		cmd                               *string
		updated                           time.Time
	}
	var targets []target
	for rows.Next() {
		var tg target
		var cid *string
		if err := rows.Scan(&tg.uuid, &tg.deviceID, &tg.status, &cid, &tg.cmd, &tg.updated); err != nil {
			rows.Close()
			return err
		}
		tg.contentID = deref(cid)
		targets = append(targets, tg)
	}
	rows.Close()
	open := 0
	for _, tg := range targets {
		switch tg.status {
		case "queued":
			open++
			if time.Since(tg.updated) > transferStepTimeout {
				t.setTarget(ctx, x.id, tg.uuid, "failed", nil, "the device was not online")
				continue
			}
			sent, err := t.send(ctx, tg.deviceID, deref(x.clientID), fileSpec{Version: 1, Operation: "unpack",
				Destination: x.destination, DestinationDir: true, Overwrite: x.overwrite,
				ContentID: tg.contentID, SHA256: deref(x.archiveSHA), Entries: x.entries},
				map[string]any{"operation": "unpack", "destination": x.destination, "overwrite": x.overwrite, "transfer_id": x.id})
			if err != nil {
				return err
			}
			switch sent.Status {
			case "dispatched":
				cmd := sent.CommandID
				t.setTarget(ctx, x.id, tg.uuid, "in_progress", &cmd, "")
			case "offline":
			default:
				t.setTarget(ctx, x.id, tg.uuid, "failed", nil, sent.Status+" "+sent.Error)
			}
		case "in_progress":
			open++
			st, reason, _, err := t.commandState(ctx, deref(tg.cmd))
			if err != nil {
				return err
			}
			if terminal(st) {
				if st == "succeeded" {
					t.setTarget(ctx, x.id, tg.uuid, "succeeded", tg.cmd, "")
				} else {
					t.setTarget(ctx, x.id, tg.uuid, "failed", tg.cmd, reason)
				}
			} else if time.Since(tg.updated) > transferStepTimeout {
				t.setTarget(ctx, x.id, tg.uuid, "failed", tg.cmd, "no answer to unpack")
			}
		}
	}
	if open > 0 {
		return nil
	}
	var failed int
	if err := t.pool.QueryRow(ctx, `SELECT count(*) FROM file_transfer_targets WHERE transfer_id = $1 AND status = 'failed'`, x.id).Scan(&failed); err != nil {
		return err
	}
	if failed > 0 {
		return t.fail(ctx, x, fmt.Sprintf("%d of %d destinations failed (source left untouched)", failed, len(targets)))
	}
	if x.move {
		_, err := t.pool.Exec(ctx, `UPDATE file_transfers SET status = 'removing_source', updated_at = now() WHERE id = $1`, x.id)
		return err
	}
	return t.succeed(ctx, x)
}

func (t *Transfers) removeSource(ctx context.Context, x transfer) error {
	if x.removeCmd == nil {
		if time.Since(x.updatedAt) > transferStepTimeout {
			return t.fail(ctx, x, "copied to every destination, but the source was not online to remove the originals")
		}
		// The agent re-checks every file's hash before deleting it.
		sent, err := t.send(ctx, x.sourceDevice, deref(x.clientID), fileSpec{Version: 1, Operation: "remove-manifest", Entries: x.entries},
			map[string]any{"operation": "remove-manifest", "source": x.sourcePath, "transfer_id": x.id})
		if err != nil {
			return err
		}
		switch sent.Status {
		case "dispatched":
			_, err = t.pool.Exec(ctx, `UPDATE file_transfers SET remove_command_id = $2, updated_at = now() WHERE id = $1`, x.id, sent.CommandID)
			return err
		case "offline":
			return nil
		default:
			return t.fail(ctx, x, "copied, but could not send remove-manifest to the source: "+sent.Status)
		}
	}
	st, reason, _, err := t.commandState(ctx, *x.removeCmd)
	if err != nil {
		return err
	}
	if !terminal(st) {
		return nil
	}
	if st != "succeeded" {
		return t.fail(ctx, x, "copied to every destination, but removing the source files failed: "+reason)
	}
	return t.succeed(ctx, x)
}

func (t *Transfers) setTarget(ctx context.Context, transferID, deviceUUID, status string, cmd *string, reason string) {
	if _, err := t.pool.Exec(ctx, `
		UPDATE file_transfer_targets SET status = $3, command_id = coalesce($4::uuid, command_id), error_message = NULLIF($5, ''),
		       updated_at = now(), content_id = CASE WHEN $3 IN ('succeeded', 'failed') THEN NULL ELSE content_id END
		WHERE transfer_id = $1 AND device_id = $2`, transferID, deviceUUID, status, cmd, reason); err != nil {
		t.log.Error("file transfer: update target", "error", err.Error())
	}
}

func (t *Transfers) fail(ctx context.Context, x transfer, reason string) error {
	return t.close(ctx, x, "failed", reason)
}

func (t *Transfers) succeed(ctx context.Context, x transfer) error {
	return t.close(ctx, x, "succeeded", "")
}

// close finishes a transfer and deletes the temporary archive.
func (t *Transfers) close(ctx context.Context, x transfer, status, reason string) error {
	if _, err := t.pool.Exec(ctx, `
		UPDATE file_transfers SET status = $2, error_message = NULLIF($3, ''), completed_at = now(), updated_at = now() WHERE id = $1`,
		x.id, status, reason); err != nil {
		return err
	}
	t.pool.Exec(ctx, `UPDATE file_transfer_targets SET content_id = NULL WHERE transfer_id = $1`, x.id) //nolint:errcheck
	if x.uploadID != nil {
		if up, err := t.uploads.get(ctx, *x.uploadID); err == nil && up != nil {
			os.Remove(t.uploads.path(up))
		}
	}
	t.log.Info("file transfer finished", "transfer_id", x.id, "status", status, "reason", reason)
	return nil
}

// Content resolves FetchContent{kind:"nsh-file"}: the content id must belong
// to this device's in-progress unpack, with the same archive digest.
func (t *Transfers) Content(ctx context.Context, contentID, sha256Hex, deviceUUID string) (path string, size int64, err error) {
	var stored string
	err = t.pool.QueryRow(ctx, `
		SELECT up.stored_name, up.size_bytes
		FROM file_transfer_targets tt
		JOIN file_transfers f ON f.id = tt.transfer_id
		JOIN agent_uploads up ON up.id = f.upload_id
		WHERE tt.content_id = $1 AND tt.device_id = $2 AND tt.status = 'in_progress' AND f.status = 'distributing'
		  AND f.archive_sha256 = lower($3)`, contentID, deviceUUID, sha256Hex).Scan(&stored, &size)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	return t.uploads.path(&Upload{stored: stored}), size, nil
}

// TransferView is GET /internal/remote/transfers?id=.
type TransferView struct {
	ID          string           `json:"transfer_id"`
	Status      string           `json:"status"`
	Source      string           `json:"source_device_id"`
	SourcePath  string           `json:"source_path"`
	Destination string           `json:"destination"`
	Move        bool             `json:"move"`
	Error       *string          `json:"error,omitempty"`
	Targets     []map[string]any `json:"destinations"`
}

func (t *Transfers) View(ctx context.Context, id string) (*TransferView, error) {
	var v TransferView
	err := t.pool.QueryRow(ctx, `
		SELECT f.id::text, f.status, d.agent_reported_id, f.source_path, f.destination, f.is_move, f.error_message
		FROM file_transfers f JOIN devices d ON d.id = f.source_device_id WHERE f.id::text = $1`, id).
		Scan(&v.ID, &v.Status, &v.Source, &v.SourcePath, &v.Destination, &v.Move, &v.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := t.pool.Query(ctx, `
		SELECT d.agent_reported_id, tt.status, tt.command_id::text, tt.error_message
		FROM file_transfer_targets tt JOIN devices d ON d.id = tt.device_id WHERE tt.transfer_id::text = $1 ORDER BY 1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	v.Targets = []map[string]any{}
	for rows.Next() {
		var dev, st string
		var cmd, e *string
		if err := rows.Scan(&dev, &st, &cmd, &e); err != nil {
			return nil, err
		}
		v.Targets = append(v.Targets, map[string]any{"device_id": dev, "status": st, "command_id": cmd, "error": e})
	}
	return &v, rows.Err()
}

func orEmptyArray(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("[]")
	}
	return b
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
