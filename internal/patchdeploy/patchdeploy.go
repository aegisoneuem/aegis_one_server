// Package patchdeploy pushes a Windows patch to a device end to end:
//
//	Create: the patch must be missing on the device (device_patch_state) ->
//	        its files from the server's scan cab index (wu_update_files): by
//	        the device's own UpdateID when an agent scan reported one, else
//	        (server-side diff) by the KB and the device's architecture in the
//	        file name -> queue the download (patchcontent)
//	Run:    downloading -> file ready on the server  -> send stage_patch
//	        staging     -> agent cached it (SUCCESS)  -> send install_patch
//	        installing  -> SUCCESS / NOT_APPLICABLE   -> succeeded
//
// The agent never fetches during install_patch; it installs only from its
// cache (filled by stage_patch via FetchContent) or a local path, so the two
// commands are sent strictly in sequence.
//
// Several files per push: a 24H2+ cumulative ships its .msu plus the
// checkpoint .msu file(s) it builds on, and the agent installs one file per
// install_patch. So each file goes through stage -> install in turn,
// checkpoints first (oldest KB first), the pushed KB last. A checkpoint the
// device already has comes back NOT_APPLICABLE and the push moves on; any
// failed file fails the push.
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
	"sort"
	"strconv"
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
	// maxPlanFiles caps one push; a cumulative has its own file plus one or
	// two checkpoints.
	maxPlanFiles = 6
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
	DeploymentID string `json:"deployment_id"`
	ResultID     string `json:"result_id"`
	KB           string `json:"kb"`
	UpdateID     string `json:"update_id"`
	File         string `json:"file"`
	// Files is the install order: checkpoints first, File last.
	Files      []PlanFile `json:"files"`
	Downloaded bool       `json:"already_downloaded"`
}

// PlanFile is one file of a push, as stored in patch_deployment_results.files.
type PlanFile struct {
	KB     string `json:"kb"`
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// installPlan orders an update's installable files for kb: the other KBs'
// files (checkpoints) first, oldest KB first, then kb's own file. Duplicates
// (same digest) are dropped.
func installPlan(files []wucatalog.File, kb string) ([]PlanFile, error) {
	var main *PlanFile
	var others []PlanFile
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f.Digest] {
			continue
		}
		seen[f.Digest] = true
		fkb := wucatalog.KBOf(f.Name)
		if fkb == "" {
			continue
		}
		pf := PlanFile{KB: "KB" + fkb, Name: f.Name, Digest: f.Digest}
		if pf.KB == kb {
			if main != nil {
				return nil, userErr("%s has two files in this update (%s, %s); can't tell which to install", kb, main.Name, pf.Name)
			}
			main = &pf
			continue
		}
		others = append(others, pf)
	}
	if main == nil {
		names := make([]string, 0, len(files))
		for _, f := range files {
			names = append(names, f.Name)
		}
		return nil, userErr("no file named for %s (files: %s)", kb, strings.Join(names, ", "))
	}
	sort.SliceStable(others, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(others[i].KB, "KB"))
		b, _ := strconv.Atoi(strings.TrimPrefix(others[j].KB, "KB"))
		if a != b {
			return a < b
		}
		return others[i].Name < others[j].Name
	})
	plan := append(others, *main)
	if len(plan) > maxPlanFiles {
		return nil, userErr("%s needs %d files, more than the %d one push handles", kb, len(plan), maxPlanFiles)
	}
	return plan, nil
}

// Create starts pushing req.KB to one device.
func (d *Deployer) Create(ctx context.Context, req Request) (*Created, error) {
	kb := normalizeKB(req.KB)
	if kb == "" {
		return nil, userErr("kb is required")
	}
	var deviceUUID string
	var arch *string
	err := d.pool.QueryRow(ctx, `
		SELECT d.id, d.architecture FROM devices d JOIN agents a ON a.device_id = d.id AND a.revoked_at IS NULL
		WHERE d.agent_reported_id = $1`, req.DeviceID).Scan(&deviceUUID, &arch)
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
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, userErr("%s is not missing on this device (no patch state for it; has the device reported its state?)", kb)
	}
	if err != nil {
		return nil, err
	}
	// Only what is missing on the device ('failed' = an earlier install
	// attempt failed, so it is still missing).
	switch state {
	case "missing", "failed":
	case "installed":
		return nil, userErr("%s is already installed on this device", kb)
	case "pending_reboot":
		return nil, userErr("%s is installed and waiting for a reboot on this device", kb)
	case "superseded":
		return nil, userErr("%s is superseded on this device; deploy the update that replaces it", kb)
	default:
		return nil, userErr("%s is not missing on this device (state %s)", kb, state)
	}

	var files []wucatalog.File
	if updateID != nil && *updateID != "" {
		if files, err = d.updateFiles(ctx, *updateID); err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, userErr("no download information for update %s in the current scan cab (not indexed yet, or not in the catalog)", *updateID)
		}
	} else {
		if deref(arch) == "" {
			return nil, userErr("the device has not reported its architecture yet")
		}
		if files, err = d.filesForKB(ctx, kb, deref(arch)); err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, userErr("no %s file for %s in the current scan cab (not indexed yet, or no package for this architecture)", deref(arch), kb)
		}
		// The checkpoint files sit in the same update as the KB's own file.
		if files, err = d.withUpdateSiblings(ctx, files[0], deref(arch)); err != nil {
			return nil, err
		}
	}
	plan, err := installPlan(files, kb)
	if err != nil {
		return nil, err
	}
	byDigest := make(map[string]wucatalog.File, len(files))
	for _, f := range files {
		byDigest[f.Digest] = f
	}
	download := make([]wucatalog.File, 0, len(plan))
	for _, pf := range plan {
		download = append(download, byDigest[pf.Digest])
	}
	notReady, err := d.content.Request(ctx, download)
	if err != nil {
		return nil, err
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	main := plan[len(plan)-1]

	out := &Created{KB: kb, UpdateID: deref(updateID), File: main.Name, Files: plan, Downloaded: notReady == 0}
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
			(deployment_id, device_id, patch_id, status, step, vendor_update_id, file_digest, files, started_at)
		VALUES ($1, $2, $3, 'in_progress', 'downloading', $4, $5, $6::jsonb, now())
		RETURNING id`, out.DeploymentID, deviceUUID, patchID, updateID, plan[0].Digest, string(planJSON)).Scan(&out.ResultID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.ConstraintName == "uq_pdr_active_device_patch" {
		return nil, userErr("%s is already being pushed to this device", kb)
	}
	if err != nil {
		return nil, fmt.Errorf("insert patch_deployment_results: %w", err)
	}
	details, _ := json.Marshal(map[string]any{
		"deployment_id": out.DeploymentID, "device_id": req.DeviceID, "kb": kb,
		"update_id": deref(updateID), "file": main.Name, "files": plan,
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
		"file", main.Name, "files", len(plan), "already_downloaded", out.Downloaded)
	d.kick()
	return out, nil
}

// filesForKB finds kb's files for one architecture in the current cab index
// by file name ("windows11.0-kb5066835-x64_<sha1>.msu"). The server-side diff
// has no UpdateID, and the same KB is one package per architecture. Files
// named for another KB (e.g. a checkpoint update) are not included; a KB with
// two different files for the same architecture is refused rather than
// guessed.
func (d *Deployer) filesForKB(ctx context.Context, kb, arch string) ([]wucatalog.File, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT DISTINCT file_digest, file_name, url FROM wu_update_files
		WHERE position($1 IN lower(file_name)) > 0 ORDER BY file_name`, strings.ToLower(kb))
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
		if "KB"+wucatalog.KBOf(f.Name) == kb && ArchMatches(f.Name, arch) {
			out = append(out, f)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 1 {
		names := make([]string, 0, len(out))
		for _, f := range out {
			names = append(names, f.Name)
		}
		return nil, userErr("%s has %d different %s files in the scan cab (%s); can't tell which this device needs",
			kb, len(out), arch, strings.Join(names, ", "))
	}
	return out, nil
}

// withUpdateSiblings returns main plus the other installable files of the
// update(s) main belongs to, for arch: that is where a cumulative's checkpoint
// .msu is listed.
func (d *Deployer) withUpdateSiblings(ctx context.Context, main wucatalog.File, arch string) ([]wucatalog.File, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT DISTINCT f.file_digest, f.file_name, f.url FROM wu_update_files f
		WHERE f.update_id IN (SELECT update_id FROM wu_update_files WHERE file_digest = $1)
		ORDER BY f.file_name`, main.Digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []wucatalog.File{main}
	for rows.Next() {
		var f wucatalog.File
		if err := rows.Scan(&f.Digest, &f.Name, &f.URL); err != nil {
			return nil, err
		}
		if f.Digest != main.Digest && ArchMatches(f.Name, arch) {
			out = append(out, f)
		}
	}
	return out, rows.Err()
}

// ArchMatches reports whether a Windows update file name is for arch (x64,
// x86, arm64): Microsoft names them "...-kb5066835-x64_<sha1>.msu".
func ArchMatches(fileName, arch string) bool {
	n, a := strings.ToLower(fileName), strings.ToLower(arch)
	return a != "" && (strings.Contains(n, "-"+a+"_") || strings.Contains(n, "-"+a+"."))
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
	installPhase                                  *string
	installReboot                                 *bool
	patchState                                    *string // device_patch_state.state now; nil = row gone (no longer applicable)
	files                                         []PlanFile
	fileIndex                                     int
}

// fileKB is the KB of the file being worked on (the pushed KB for a one-file
// row created before 0022).
func (x row) fileKB() string {
	if x.fileIndex < len(x.files) {
		return x.files[x.fileIndex].KB
	}
	return x.kb
}

// fileLabel prefixes reasons with which file it is, when there are several.
func (x row) fileLabel() string {
	if len(x.files) < 2 || x.fileIndex >= len(x.files) {
		return ""
	}
	return fmt.Sprintf("file %d/%d (%s): ", x.fileIndex+1, len(x.files), x.files[x.fileIndex].KB)
}

func (x row) lastFile() bool { return x.fileIndex >= len(x.files)-1 }

func (d *Deployer) advanceAll(ctx context.Context) error {
	rows, err := d.pool.Query(ctx, `
		SELECT r.id, r.deployment_id, dv.agent_reported_id, COALESCE(a.id::text, ''), p.kb_or_advisory_id, r.step,
		       pd.created_by_api_client_id::text,
		       pc.state, pc.file_name, pc.sha256_hash, pc.last_error,
		       r.stage_command_id::text, r.install_command_id::text,
		       sc.status, ic.status, COALESCE(sc.dispatched_at, sc.issued_at), COALESCE(ic.dispatched_at, ic.issued_at),
		       sc.result->>'reason', ic.result->>'reason', ic.result->>'phase', (ic.result->>'reboot_required')::boolean,
		       dps.state, r.files, r.file_index
		FROM patch_deployment_results r
		JOIN patch_deployments pd ON pd.id = r.deployment_id
		JOIN devices dv ON dv.id = r.device_id
		JOIN patch_catalog p ON p.id = r.patch_id
		LEFT JOIN agents a ON a.device_id = dv.id AND a.revoked_at IS NULL
		LEFT JOIN patch_content pc ON pc.file_digest = r.file_digest
		LEFT JOIN agent_commands sc ON sc.id = r.stage_command_id
		LEFT JOIN agent_commands ic ON ic.id = r.install_command_id
		LEFT JOIN device_patch_state dps ON dps.device_id = r.device_id AND dps.patch_id = r.patch_id
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
			&x.stageStatus, &x.installStatus, &x.stageAt, &x.installAt, &x.stageReason, &x.installReason,
			&x.installPhase, &x.installReboot, &x.patchState, &x.files, &x.fileIndex); err != nil {
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
	// Before sending the next command, respect what the device's latest scan
	// says: only a still-missing patch gets staged/installed. (While
	// installing, the install command's own result decides.)
	if x.step != "installing" {
		switch st := deref(x.patchState); st {
		case "missing", "failed":
		case "installed", "pending_reboot":
			return d.finish(ctx, x, true, "already "+st+" per the device's latest scan")
		case "":
			return d.finish(ctx, x, false, "no longer applicable per the device's latest scan")
		default:
			return d.finish(ctx, x, false, "no longer missing per the device's latest scan (state "+st+")")
		}
	}
	switch x.step {
	case "downloading":
		switch deref(x.contentState) {
		case "ready":
			return d.sendStep(ctx, x, "stage_patch", "staging")
		case "failed":
			return d.finish(ctx, x, false, x.fileLabel()+"server download failed: "+deref(x.contentErr))
		}
		return nil // pending / downloading

	case "staging":
		switch deref(x.stageStatus) {
		case "succeeded":
			return d.sendStep(ctx, x, "install_patch", "installing")
		case "failed", "rejected_signature", "expired":
			return d.finish(ctx, x, false, fmt.Sprintf("%sstage_patch %s: %s", x.fileLabel(), deref(x.stageStatus), deref(x.stageReason)))
		}
		if timedOut(x.stageAt) {
			return d.finish(ctx, x, false, x.fileLabel()+"no final answer to stage_patch from the agent")
		}
		return nil

	case "installing":
		switch deref(x.installStatus) {
		case "succeeded": // SUCCESS or NOT_APPLICABLE (e.g. a checkpoint the device already has)
			if !x.lastFile() {
				return d.nextFile(ctx, x)
			}
			return d.finish(ctx, x, true, "")
		case "failed", "rejected_signature", "expired":
			return d.finish(ctx, x, false, fmt.Sprintf("%sinstall_patch %s: %s", x.fileLabel(), deref(x.installStatus), deref(x.installReason)))
		}
		if timedOut(x.installAt) {
			return d.finish(ctx, x, false, x.fileLabel()+"no final answer to install_patch from the agent")
		}
	}
	return nil
}

func timedOut(at *time.Time) bool { return at != nil && time.Since(*at) > commandTimeout }

// fileResult is the file_results entry for x's current file, once its
// install_patch has a final answer; nil before that.
func (x row) fileResult() []byte {
	if x.step != "installing" || x.installID == nil || x.fileIndex >= len(x.files) {
		return nil
	}
	f := x.files[x.fileIndex]
	b, _ := json.Marshal(map[string]any{
		"kb": f.KB, "file": f.Name, "command_id": deref(x.installID), "status": deref(x.installStatus),
		"phase": deref(x.installPhase), "reboot_required": x.installReboot != nil && *x.installReboot,
		"reason": deref(x.installReason),
	})
	return b
}

// nextFile records the finished file and moves x to the next one in the plan.
// The file was requested for download at Create, so it is usually ready.
func (d *Deployer) nextFile(ctx context.Context, x row) error {
	next := x.files[x.fileIndex+1]
	tag, err := d.pool.Exec(ctx, `
		UPDATE patch_deployment_results SET
			file_results = file_results || jsonb_build_array($3::jsonb),
			file_index = $2 + 1, file_digest = $4, step = 'downloading',
			stage_command_id = NULL, install_command_id = NULL, updated_at = now()
		WHERE id = $1 AND file_index = $2 AND status = 'in_progress'`,
		x.id, x.fileIndex, string(x.fileResult()), next.Digest)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		d.log.Info("patch deploy: file done, next file", "result_id", x.id, "device_id", x.deviceID, "done_kb", x.fileKB(),
			"phase", deref(x.installPhase), "reboot_required", x.installReboot != nil && *x.installReboot,
			"next_kb", next.KB, "file", fmt.Sprintf("%d/%d", x.fileIndex+2, len(x.files)))
		d.kick()
	}
	return nil
}

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
	spec := &aegisonev1.InstallPatchSpec{Kb: x.fileKB(), FilePath: deref(x.fileName), ExpectedHash: deref(x.sha256), HashAlgorithm: "sha256"}
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
		IdempotencyKey:      fmt.Sprintf("patchdeploy:%s:%d:%s:%d", x.id, x.fileIndex, cmdType, attempt),
		IssuedByAPIClientID: deref(x.clientID), IssuedByLabel: "patch deployment " + x.deploymentID,
		SourceJobType: "patch_deployment", SourceJobID: x.deploymentID,
	})
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("idempotency key reused by command %s", existing.ID)
	}
	msg := &aegisonev1.ServerMessage{Payload: &aegisonev1.ServerMessage_Command{Command: commands.Envelope(cmdID, cmdType, payload, sig, "patch_deployment:"+x.deploymentID)}}
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
	d.log.Info("patch deploy: command sent", "result_id", x.id, "device_id", x.deviceID, "kb", x.kb, "file_kb", spec.Kb,
		"command", cmdType, "command_id", cmdID)
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
	var fileResult *string
	if b := x.fileResult(); b != nil {
		s := string(b)
		fileResult = &s
	}
	if _, err := tx.Exec(ctx, `
		UPDATE patch_deployment_results SET status = $2, error_message = NULLIF($3, ''), completed_at = now(), updated_at = now(),
			file_results = CASE WHEN $4::jsonb IS NULL THEN file_results ELSE file_results || jsonb_build_array($4::jsonb) END
		WHERE id = $1 AND status = 'in_progress'`, x.id, status, reason, fileResult); err != nil {
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
