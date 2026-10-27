// Package patchdeploy pushes a Windows patch to a device end to end:
//
//	Create: resolve the device's own UpdateID for the KB (device_patch_state,
//	        from its scan) -> the update's files (wu_update_files, from the scan
//	        cab) -> queue the download (patchcontent)
//	Run:    downloading -> file ready on the server  -> send stage_patch
//	        staging     -> agent cached it (SUCCESS)  -> send install_patch
//	        installing  -> SUCCESS / NOT_APPLICABLE   -> succeeded
//
// The agent never fetches during install_patch; it installs only from its
// cache (filled by stage_patch via FetchContent) or a local path, so the two
// commands are sent strictly in sequence.
//
// One file per push for now: the .msu named for the pushed KB. Other
// installable files of the same update (e.g. the checkpoint .msu a 24H2
// cumulative needs first) are recorded in skipped_files until the agent can
// install several files in one go.
//
// State lives in patch_deployments / patch_deployment_results; Run polls it, so
// a server restart resumes where it left off. A device that is offline just
// waits in its current step. Run assumes a single server instance.
package patchdeploy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/commands"
	"aegis-one/internal/patchcontent"
	"aegis-one/internal/signing"
	"aegis-one/internal/wucatalog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

const (
	tick = 5 * time.Second
	// commandTimeout fails a step whose command got no final answer: the agent
	// may have lost it (e.g. it restarted mid-fetch) and nothing re-sends it.
	commandTimeout = 6 * time.Hour
)

type Dispatcher interface {
	Dispatch(deviceID string, msg *aegisonev1.ServerMessage) error
	Connected(deviceID string) bool
}

type Deployer struct {
	pool    *pgxpool.Pool
	content *patchcontent.Store
	cmds    *commands.Store
	disp    Dispatcher
	key     ed25519.PrivateKey
	keyID   string
	log     *slog.Logger
	wake    chan struct{}
}

func New(pool *pgxpool.Pool, content *patchcontent.Store, cmds *commands.Store, disp Dispatcher,
	key ed25519.PrivateKey, keyID string, log *slog.Logger) *Deployer {
	return &Deployer{pool: pool, content: content, cmds: cmds, disp: disp, key: key, keyID: keyID, log: log,
		wake: make(chan struct{}, 1)}
}

// UserError is a request the caller can fix (unknown device, nothing to
// download, ...), as opposed to a server failure.
type UserError struct{ msg string }

func (e *UserError) Error() string { return e.msg }

func userErr(format string, a ...any) error { return &UserError{fmt.Sprintf(format, a...)} }

type Request struct {
	DeviceID   string // agent-reported device_id
	KB         string
	ClientID   string // api_clients.id of the caller
	ClientName string
}

type Created struct {
	DeploymentID string   `json:"deployment_id"`
	ResultID     string   `json:"result_id"`
	KB           string   `json:"kb"`
	UpdateID     string   `json:"update_id"`
	File         string   `json:"file"`
	SkippedFiles []string `json:"skipped_files,omitempty"`
	Downloaded   bool     `json:"already_downloaded"`
}

// Create starts pushing req.KB to one device.
func (d *Deployer) Create(ctx context.Context, req Request) (*Created, error) {
	kb := normalizeKB(req.KB)
	if kb == "" {
		return nil, userErr("kb is required")
	}
	var deviceUUID string
	err := d.pool.QueryRow(ctx, `
		SELECT d.id FROM devices d JOIN agents a ON a.device_id = d.id AND a.revoked_at IS NULL
		WHERE d.agent_reported_id = $1`, req.DeviceID).Scan(&deviceUUID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, userErr("unknown device_id %q (never connected, or its agent is revoked)", req.DeviceID)
	}
	if err != nil {
		return nil, err
	}
	var patchID string
	err = d.pool.QueryRow(ctx, `SELECT id FROM patch_catalog WHERE vendor = 'microsoft' AND kb_or_advisory_id = $1`, kb).Scan(&patchID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, userErr("%s is not in the patch catalog", kb)
	}
	if err != nil {
		return nil, err
	}
	var updateID *string
	var state string
	err = d.pool.QueryRow(ctx, `SELECT vendor_update_id, state FROM device_patch_state WHERE device_id = $1 AND patch_id = $2`,
		deviceUUID, patchID).Scan(&updateID, &state)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (updateID == nil || *updateID == "")) {
		return nil, userErr("device has not reported %s as missing in a patch scan (scan it first)", kb)
	}
	if err != nil {
		return nil, err
	}
	if state == "installed" {
		return nil, userErr("%s is already installed on this device", kb)
	}

	files, err := d.updateFiles(ctx, *updateID)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, userErr("no download information for update %s in the current scan cab (not indexed yet, or not in the catalog)", *updateID)
	}
	var main *wucatalog.File
	skipped := []string{} // non-nil: the column is NOT NULL
	for i := range files {
		if main == nil && "KB"+wucatalog.KBOf(files[i].Name) == kb {
			main = &files[i]
			continue
		}
		skipped = append(skipped, files[i].Name)
	}
	if main == nil {
		return nil, userErr("update %s has no file named for %s (files: %s)", *updateID, kb, strings.Join(skipped, ", "))
	}

	notReady, err := d.content.Request(ctx, []wucatalog.File{*main})
	if err != nil {
		return nil, err
	}

	out := &Created{KB: kb, UpdateID: *updateID, File: main.Name, SkippedFiles: skipped, Downloaded: notReady == 0}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if err := tx.QueryRow(ctx, `
		INSERT INTO patch_deployments (name, patch_ids, rollout_strategy, reboot_behavior, status, created_by_api_client_id)
		VALUES ($1, ARRAY[$2::uuid], 'all_at_once', 'no_reboot', 'running', $3)
		RETURNING id`, fmt.Sprintf("%s -> %s", kb, req.DeviceID), patchID, req.ClientID).Scan(&out.DeploymentID); err != nil {
		return nil, fmt.Errorf("insert patch_deployments: %w", err)
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO patch_deployment_results
			(deployment_id, device_id, patch_id, status, step, vendor_update_id, file_digest, skipped_files, started_at)
		VALUES ($1, $2, $3, 'in_progress', 'downloading', $4, $5, $6, now())
		RETURNING id`, out.DeploymentID, deviceUUID, patchID, *updateID, main.Digest, skipped).Scan(&out.ResultID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.ConstraintName == "uq_pdr_active_device_patch" {
		return nil, userErr("%s is already being pushed to this device", kb)
	}
	if err != nil {
		return nil, fmt.Errorf("insert patch_deployment_results: %w", err)
	}
	details, _ := json.Marshal(map[string]any{
		"deployment_id": out.DeploymentID, "device_id": req.DeviceID, "kb": kb,
		"update_id": *updateID, "file": main.Name, "skipped_files": skipped,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', $1, $2, 'patch.deploy.create', 'patch_deployment', $3, $4::jsonb)`,
		req.ClientID, req.ClientName, out.DeploymentID, string(details)); err != nil {
		return nil, fmt.Errorf("insert audit_log: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	d.log.Info("patch deployment created", "deployment_id", out.DeploymentID, "device_id", req.DeviceID, "kb", kb,
		"file", main.Name, "skipped_files", len(skipped), "already_downloaded", out.Downloaded)
	d.kick()
	return out, nil
}

func (d *Deployer) updateFiles(ctx context.Context, updateID string) ([]wucatalog.File, error) {
	rows, err := d.pool.Query(ctx, `SELECT file_digest, file_name, url FROM wu_update_files WHERE update_id = $1 ORDER BY file_name`, updateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wucatalog.File
	for rows.Next() {
		var f wucatalog.File
		if err := rows.Scan(&f.Digest, &f.Name, &f.URL); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (d *Deployer) kick() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run advances active deployments until ctx ends.
func (d *Deployer) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if err := d.advanceAll(ctx); err != nil && ctx.Err() == nil {
			d.log.Warn("patch deploy: advance", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.wake:
		}
	}
}

// row is one active patch_deployment_results row with everything needed to
// decide its next move.
type row struct {
	id, deploymentID, deviceID, agentID, kb, step string
	clientID                                      *string
	contentState, fileName, sha256, contentErr    *string
	stageID, installID                            *string
	stageStatus, installStatus                    *string
	stageAt, installAt                            *time.Time
	stageReason, installReason                    *string
}

func (d *Deployer) advanceAll(ctx context.Context) error {
	rows, err := d.pool.Query(ctx, `
		SELECT r.id, r.deployment_id, dv.agent_reported_id, COALESCE(a.id::text, ''), p.kb_or_advisory_id, r.step,
		       pd.created_by_api_client_id::text,
		       pc.state, pc.file_name, pc.sha256_hash, pc.last_error,
		       r.stage_command_id::text, r.install_command_id::text,
		       sc.status, ic.status, COALESCE(sc.dispatched_at, sc.issued_at), COALESCE(ic.dispatched_at, ic.issued_at),
		       sc.result->>'reason', ic.result->>'reason'
		FROM patch_deployment_results r
		JOIN patch_deployments pd ON pd.id = r.deployment_id
		JOIN devices dv ON dv.id = r.device_id
		JOIN patch_catalog p ON p.id = r.patch_id
		LEFT JOIN agents a ON a.device_id = dv.id AND a.revoked_at IS NULL
		LEFT JOIN patch_content pc ON pc.file_digest = r.file_digest
		LEFT JOIN agent_commands sc ON sc.id = r.stage_command_id
		LEFT JOIN agent_commands ic ON ic.id = r.install_command_id
		WHERE r.status = 'in_progress' AND r.step IS NOT NULL
		ORDER BY r.updated_at LIMIT 500`)
	if err != nil {
		return err
	}
	var active []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.id, &x.deploymentID, &x.deviceID, &x.agentID, &x.kb, &x.step, &x.clientID,
			&x.contentState, &x.fileName, &x.sha256, &x.contentErr, &x.stageID, &x.installID,
			&x.stageStatus, &x.installStatus, &x.stageAt, &x.installAt, &x.stageReason, &x.installReason); err != nil {
			rows.Close()
			return err
		}
		active = append(active, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range active {
		if err := d.advance(ctx, x); err != nil {
			d.log.Warn("patch deploy: advance result", "result_id", x.id, "device_id", x.deviceID, "error", err.Error())
		}
	}
	return nil
}

func (d *Deployer) advance(ctx context.Context, x row) error {
	if x.agentID == "" {
		return d.finish(ctx, x, false, "the device's agent was revoked")
	}
	switch x.step {
	case "downloading":
		switch deref(x.contentState) {
		case "ready":
			return d.sendStep(ctx, x, "stage_patch", "staging")
		case "failed":
			return d.finish(ctx, x, false, "server download failed: "+deref(x.contentErr))
		}
		return nil // pending / downloading

	case "staging":
		switch deref(x.stageStatus) {
		case "succeeded":
			return d.sendStep(ctx, x, "install_patch", "installing")
		case "failed", "rejected_signature", "expired":
			return d.finish(ctx, x, false, fmt.Sprintf("stage_patch %s: %s", deref(x.stageStatus), deref(x.stageReason)))
		}
		if timedOut(x.stageAt) {
			return d.finish(ctx, x, false, "no final answer to stage_patch from the agent")
		}
		return nil

	case "installing":
		switch deref(x.installStatus) {
		case "succeeded":
			return d.finish(ctx, x, true, "")
		case "failed", "rejected_signature", "expired":
			return d.finish(ctx, x, false, fmt.Sprintf("install_patch %s: %s", deref(x.installStatus), deref(x.installReason)))
		}
		if timedOut(x.installAt) {
			return d.finish(ctx, x, false, "no final answer to install_patch from the agent")
		}
	}
	return nil
}

func timedOut(at *time.Time) bool { return at != nil && time.Since(*at) > commandTimeout }

// sendStep signs and dispatches cmdType for x and moves it to nextStep. An
// offline device is left as is and retried on a later tick.
func (d *Deployer) sendStep(ctx context.Context, x row, cmdType, nextStep string) error {
	if !d.disp.Connected(x.deviceID) {
		return nil
	}
	var attempt int
	if err := d.pool.QueryRow(ctx, `
		UPDATE patch_deployment_results SET attempt_count = attempt_count + 1, updated_at = now()
		WHERE id = $1 RETURNING attempt_count`, x.id).Scan(&attempt); err != nil {
		return err
	}
	// file_path only carries the extension (.msu/.cab) the agent keeps for
	// DISM; the bytes come from its cache, filled by stage_patch.
	spec := &aegisonev1.InstallPatchSpec{Kb: x.kb, FilePath: deref(x.fileName), ExpectedHash: deref(x.sha256), HashAlgorithm: "sha256"}
	payload, err := proto.Marshal(spec)
	if err != nil {
		return err
	}
	id, err := commands.NewID()
	if err != nil {
		return err
	}
	sig := signing.SignCommand(d.key, cmdType, id, payload)
	cmdID, existing, err := d.cmds.Create(ctx, commands.Issue{
		ID: id, AgentUUID: x.agentID, DeviceID: x.deviceID, Type: cmdType,
		Payload: map[string]any{
			"kb": spec.Kb, "file_path": spec.FilePath, "expected_hash": spec.ExpectedHash,
			"hash_algorithm": spec.HashAlgorithm, "patch_deployment_id": x.deploymentID,
		},
		Signature: sig, SigningKeyID: d.keyID,
		IdempotencyKey:      fmt.Sprintf("patchdeploy:%s:%s:%d", x.id, cmdType, attempt),
		IssuedByAPIClientID: deref(x.clientID), IssuedByLabel: "patch deployment " + x.deploymentID,
		SourceJobType: "patch_deployment", SourceJobID: x.deploymentID,
	})
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("idempotency key reused by command %s", existing.ID)
	}
	msg := &aegisonev1.ServerMessage{Payload: &aegisonev1.ServerMessage_Command{Command: &aegisonev1.Command{
		CommandId: cmdID, Type: cmdType, Payload: payload, Signature: sig,
	}}}
	if err := d.disp.Dispatch(x.deviceID, msg); err != nil {
		if mErr := d.cmds.MarkFailed(ctx, cmdID, err.Error()); mErr != nil {
			d.log.Error("patch deploy: mark command failed", "command_id", cmdID, "error", mErr.Error())
		}
		d.log.Info("patch deploy: dispatch failed, will retry", "result_id", x.id, "command", cmdType, "error", err.Error())
		return nil
	}
	if err := d.cmds.MarkDispatched(ctx, cmdID); err != nil {
		d.log.Error("patch deploy: mark command dispatched", "command_id", cmdID, "error", err.Error())
	}
	col := "stage_command_id"
	if cmdType == "install_patch" {
		col = "install_command_id"
	}
	if _, err := d.pool.Exec(ctx, `UPDATE patch_deployment_results SET step = $2, `+col+` = $3, updated_at = now() WHERE id = $1`,
		x.id, nextStep, cmdID); err != nil {
		return err
	}
	d.log.Info("patch deploy: command sent", "result_id", x.id, "device_id", x.deviceID, "kb", x.kb, "command", cmdType, "command_id", cmdID)
	return nil
}

// finish closes a result and, when it was the deployment's last open one, the
// deployment.
func (d *Deployer) finish(ctx context.Context, x row, ok bool, reason string) error {
	status := "succeeded"
	if !ok {
		status = "failed"
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, `
		UPDATE patch_deployment_results SET status = $2, error_message = NULLIF($3, ''), completed_at = now(), updated_at = now()
		WHERE id = $1 AND status = 'in_progress'`, x.id, status, reason); err != nil {
		return err
	}
	if !ok {
		// Visible next to the patch in compliance views; the next scan still
		// decides missing vs installed.
		if _, err := tx.Exec(ctx, `
			UPDATE device_patch_state SET install_attempts = install_attempts + 1, last_error = $2
			WHERE (device_id, patch_id) = (SELECT device_id, patch_id FROM patch_deployment_results WHERE id = $1)`, x.id, reason); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE patch_deployments SET status = CASE
			WHEN EXISTS (SELECT 1 FROM patch_deployment_results WHERE deployment_id = $1 AND status = 'failed') THEN 'failed'
			ELSE 'completed' END
		WHERE id = $1 AND status = 'running'
		  AND NOT EXISTS (SELECT 1 FROM patch_deployment_results WHERE deployment_id = $1 AND status IN ('queued', 'in_progress'))`,
		x.deploymentID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	d.log.Info("patch deploy: finished", "result_id", x.id, "device_id", x.deviceID, "kb", x.kb, "status", status, "reason", reason)
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func normalizeKB(kb string) string {
	kb = strings.ToUpper(strings.TrimSpace(kb))
	if kb == "" {
		return ""
	}
	if !strings.HasPrefix(kb, "KB") {
		kb = "KB" + kb
	}
	return kb
}
