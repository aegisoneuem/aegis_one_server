package softwaredist

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
	"aegis-one/internal/signing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

const (
	tick = 5 * time.Second
	// MaxDevices caps one deployment request.
	MaxDevices = 1000
	// answerGrace is added to the package's own timeout (default 30 minutes on
	// the agent) before a dispatched command with no final answer is failed:
	// the fetch, the install queue and an agent restart all take time.
	answerGrace = 6 * time.Hour
	// agentDefaultTimeout is the agent's per-install limit when the package sets none.
	agentDefaultTimeout = 30 * time.Minute
)

type Dispatcher interface {
	Dispatch(deviceID string, msg *aegisonev1.ServerMessage) error
	Connected(deviceID string) bool
}

type Deployer struct {
	pool  *pgxpool.Pool
	pkgs  *Store
	cmds  *commands.Store
	disp  Dispatcher
	key   ed25519.PrivateKey
	keyID string
	log   *slog.Logger
	wake  chan struct{}
}

func NewDeployer(pool *pgxpool.Pool, pkgs *Store, cmds *commands.Store, disp Dispatcher,
	key ed25519.PrivateKey, keyID string, log *slog.Logger) *Deployer {
	return &Deployer{pool: pool, pkgs: pkgs, cmds: cmds, disp: disp, key: key, keyID: keyID, log: log,
		wake: make(chan struct{}, 1)}
}

type DeployRequest struct {
	PackageID  string
	Action     string   // install | uninstall
	DeviceIDs  []string // agent-reported device ids
	ClientID   string
	ClientName string
	CanScript  bool // caller holds software.script
}

type DeployCreated struct {
	DeploymentID string `json:"deployment_id"`
	PackageID    string `json:"package_id"`
	Package      string `json:"package"`
	Action       string `json:"action"`
	Devices      int    `json:"devices"`
}

// Create queues a deployment of one package to a list of devices. Devices
// that are offline wait in 'queued' until they connect.
func (d *Deployer) Create(ctx context.Context, req DeployRequest) (*DeployCreated, error) {
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "install"
	}
	if action != "install" && action != "uninstall" {
		return nil, userErr("action must be install or uninstall")
	}
	devices := dedupe(req.DeviceIDs)
	if len(devices) == 0 {
		return nil, userErr("device_ids is required")
	}
	if len(devices) > MaxDevices {
		return nil, userErr("at most %d devices per deployment", MaxDevices)
	}
	pkg, err := d.pkgs.Get(ctx, req.PackageID)
	if err != nil {
		return nil, err
	}
	if pkg == nil {
		return nil, userErr("unknown package_id %q", req.PackageID)
	}
	if IsScript(pkg.InstallerType) && !req.CanScript {
		return nil, &PermissionError{"deploying a script package needs the software.script permission"}
	}

	// Resolve every device first so the whole request is accepted or refused.
	rows, err := d.pool.Query(ctx, `
		SELECT d.agent_reported_id, d.id FROM devices d JOIN agents a ON a.device_id = d.id AND a.revoked_at IS NULL
		WHERE d.agent_reported_id = ANY($1)`, devices)
	if err != nil {
		return nil, err
	}
	uuids := make(map[string]string, len(devices))
	for rows.Next() {
		var rid, id string
		if err := rows.Scan(&rid, &id); err != nil {
			rows.Close()
			return nil, err
		}
		uuids[rid] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var unknown []string
	for _, dev := range devices {
		if _, ok := uuids[dev]; !ok {
			unknown = append(unknown, dev)
		}
	}
	if len(unknown) > 0 {
		if len(unknown) > 10 {
			unknown = append(unknown[:10], fmt.Sprintf("... (%d more)", len(unknown)-10))
		}
		return nil, userErr("unknown device_ids (never connected, or agent revoked): %s", strings.Join(unknown, ", "))
	}

	dbAction := action
	if action == "uninstall" {
		dbAction = "remove" // 0001's CHECK
	}
	out := &DeployCreated{PackageID: pkg.ID, Package: pkg.Name + " " + pkg.Version, Action: action, Devices: len(devices)}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if err := tx.QueryRow(ctx, `
		INSERT INTO software_deployments (package_id, action, schedule_type, status, name, created_by_api_client_id)
		VALUES ($1, $2, 'immediate', 'running', $3, $4) RETURNING id`,
		pkg.ID, dbAction, fmt.Sprintf("%s %s %s -> %d device(s)", action, pkg.Name, pkg.Version, len(devices)), req.ClientID,
	).Scan(&out.DeploymentID); err != nil {
		return nil, fmt.Errorf("insert software_deployments: %w", err)
	}
	ids := make([]string, 0, len(devices))
	for _, dev := range devices {
		ids = append(ids, uuids[dev])
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO software_deployment_results (deployment_id, device_id, package_id, status)
		SELECT $1, unnest($2::uuid[]), $3, 'queued'`, out.DeploymentID, ids, pkg.ID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.ConstraintName == "uq_sdr_active_device_package" {
		return nil, userErr("%s is already being deployed to one of these devices; wait for it to finish", out.Package)
	}
	if err != nil {
		return nil, fmt.Errorf("insert software_deployment_results: %w", err)
	}
	details, _ := json.Marshal(map[string]any{
		"deployment_id": out.DeploymentID, "package_id": pkg.ID, "package": out.Package, "action": action,
		"installer_type": pkg.InstallerType, "script": IsScript(pkg.InstallerType), "sha256": pkg.SHA256,
		"device_ids": devices,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', $1, $2, 'software.deploy.create', 'software_deployment', $3, $4::jsonb)`,
		req.ClientID, req.ClientName, out.DeploymentID, string(details)); err != nil {
		return nil, fmt.Errorf("insert audit_log: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	d.log.Info("software deployment created", "deployment_id", out.DeploymentID, "package_id", pkg.ID,
		"package", out.Package, "action", action, "devices", len(devices))
	d.kick()
	return out, nil
}

// PermissionError is a request the caller isn't allowed to make.
type PermissionError struct{ msg string }

func (e *PermissionError) Error() string { return e.msg }

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func (d *Deployer) kick() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run advances active deployments until ctx ends. State is in the database,
// so a restart resumes; it assumes a single server instance.
func (d *Deployer) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if err := d.advanceAll(ctx); err != nil && ctx.Err() == nil {
			d.log.Warn("software deploy: advance", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.wake:
		}
	}
}

// result is one active software_deployment_results row.
type result struct {
	id, deploymentID, deviceID, agentID, status, action string
	clientID                                            *string
	pkg                                                 *Package
	commandID, cmdStatus                                *string
	cmdAt                                               *time.Time
	cmdResult                                           []byte
}

func (d *Deployer) advanceAll(ctx context.Context) error {
	rows, err := d.pool.Query(ctx, `
		SELECT r.id, r.deployment_id, dv.agent_reported_id, coalesce(a.id::text, ''), r.status, sd.action,
		       sd.created_by_api_client_id::text, r.command_id::text, c.status, coalesce(c.dispatched_at, c.issued_at), c.result,
		       p.id, p.name, p.version, p.installer_type, coalesce(p.file_name, ''), p.sha256_hash, coalesce(p.size_bytes, 0),
		       coalesce(p.silent_args, ''), coalesce(p.product_code, ''), coalesce(p.uninstall_key, ''), coalesce(p.display_name, ''),
		       p.success_exit_codes, coalesce(p.timeout_seconds, 0), p.require_signature, p.created_at, coalesce(p.storage_name, '')
		FROM software_deployment_results r
		JOIN software_deployments sd ON sd.id = r.deployment_id
		JOIN software_packages p ON p.id = r.package_id
		JOIN devices dv ON dv.id = r.device_id
		LEFT JOIN agents a ON a.device_id = dv.id AND a.revoked_at IS NULL
		LEFT JOIN agent_commands c ON c.id = r.command_id
		WHERE r.status IN ('queued', 'in_progress')
		ORDER BY r.updated_at LIMIT 1000`)
	if err != nil {
		return err
	}
	var active []result
	for rows.Next() {
		var x result
		var p Package
		if err := rows.Scan(&x.id, &x.deploymentID, &x.deviceID, &x.agentID, &x.status, &x.action,
			&x.clientID, &x.commandID, &x.cmdStatus, &x.cmdAt, &x.cmdResult,
			&p.ID, &p.Name, &p.Version, &p.InstallerType, &p.FileName, &p.SHA256, &p.SizeBytes,
			&p.SilentArgs, &p.ProductCode, &p.UninstallKey, &p.DisplayName,
			&p.SuccessExitCodes, &p.TimeoutSeconds, &p.RequireSignature, &p.CreatedAt, &p.storageName); err != nil {
			rows.Close()
			return err
		}
		x.pkg = &p
		active = append(active, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range active {
		if err := d.advance(ctx, x); err != nil {
			d.log.Warn("software deploy: advance result", "result_id", x.id, "device_id", x.deviceID, "error", err.Error())
		}
	}
	return nil
}

func (d *Deployer) advance(ctx context.Context, x result) error {
	if x.agentID == "" {
		return d.finish(ctx, x, "failed", "the device's agent was revoked", nil)
	}
	if x.status == "queued" || x.commandID == nil {
		return d.send(ctx, x)
	}
	var res agentResult
	if len(x.cmdResult) > 0 {
		_ = json.Unmarshal(x.cmdResult, &res) // best effort: shown to the operator only
	}
	switch deref(x.cmdStatus) {
	case "succeeded":
		return d.finish(ctx, x, "succeeded", "", &res)
	case "failed", "rejected_signature", "expired":
		reason := res.Reason
		if reason == "" {
			reason = res.Message
		}
		if reason == "" {
			reason = res.Error
		}
		return d.finish(ctx, x, "failed", fmt.Sprintf("software_deploy %s: %s", deref(x.cmdStatus), reason), &res)
	}
	limit := agentDefaultTimeout
	if x.pkg.TimeoutSeconds > 0 {
		limit = time.Duration(x.pkg.TimeoutSeconds) * time.Second
	}
	if x.cmdAt != nil && time.Since(*x.cmdAt) > limit+answerGrace {
		return d.finish(ctx, x, "failed", "no final answer to software_deploy from the agent", nil)
	}
	return nil
}

// agentResult is the part of agent_commands.result we show (written by
// commands.ApplyActionStatus / ApplyCommandResult / MarkFailed).
type agentResult struct {
	Phase          string `json:"phase"`
	Reason         string `json:"reason"`
	Detail         string `json:"detail"`
	ExitCode       *int32 `json:"exit_code"`
	RebootRequired *bool  `json:"reboot_required"`
	Message        string `json:"message"`
	Error          string `json:"error"`
}

// Spec builds the agent's SoftwareDeploySpec for p.
func Spec(p *Package, action string) *aegisonev1.SoftwareDeploySpec {
	return &aegisonev1.SoftwareDeploySpec{
		PackageId:     p.ID,
		Name:          p.Name,
		Version:       p.Version,
		Action:        action,
		InstallerType: p.InstallerType,
		// Not a real path: the agent takes the extension from it (to name the
		// fetched file so the right program runs it). A file of that exact name
		// in the agent's drop folder would be used instead, but only if it
		// matches expected_hash.
		FilePath:         p.ID + p.Ext(),
		ExpectedHash:     p.SHA256,
		HashAlgorithm:    "sha256",
		SilentArgs:       p.SilentArgs,
		SuccessExitCodes: p.SuccessExitCodes,
		TimeoutSeconds:   p.TimeoutSeconds,
		ContentId:        p.ID,
		RequireSignature: p.RequireSignature,
		ProductCode:      p.ProductCode,
		UninstallKey:     p.UninstallKey,
		DisplayName:      p.DisplayName,
	}
}

// send signs and dispatches software_deploy. An offline device stays queued.
func (d *Deployer) send(ctx context.Context, x result) error {
	if !d.disp.Connected(x.deviceID) {
		return nil
	}
	action := x.action
	if action == "remove" {
		action = "uninstall"
	}
	var attempt int
	if err := d.pool.QueryRow(ctx, `
		UPDATE software_deployment_results SET attempt_count = attempt_count + 1, updated_at = now()
		WHERE id = $1 RETURNING attempt_count`, x.id).Scan(&attempt); err != nil {
		return err
	}
	spec := Spec(x.pkg, action)
	payload, err := proto.Marshal(spec)
	if err != nil {
		return err
	}
	id, err := commands.NewID()
	if err != nil {
		return err
	}
	const cmdType = "software_deploy"
	sig := signing.SignCommand(d.key, cmdType, id, payload)
	cmdID, existing, err := d.cmds.Create(ctx, commands.Issue{
		ID: id, AgentUUID: x.agentID, DeviceID: x.deviceID, Type: cmdType,
		Payload: map[string]any{
			"package_id": spec.PackageId, "name": spec.Name, "version": spec.Version, "action": spec.Action,
			"installer_type": spec.InstallerType, "expected_hash": spec.ExpectedHash, "silent_args": spec.SilentArgs,
			"product_code": spec.ProductCode, "uninstall_key": spec.UninstallKey, "display_name": spec.DisplayName,
			"require_signature": spec.RequireSignature, "software_deployment_id": x.deploymentID,
		},
		Signature: sig, SigningKeyID: d.keyID,
		IdempotencyKey:      fmt.Sprintf("softwaredeploy:%s:%d", x.id, attempt),
		IssuedByAPIClientID: deref(x.clientID), IssuedByLabel: "software deployment " + x.deploymentID,
		SourceJobType: "software_deployment", SourceJobID: x.deploymentID,
	})
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("idempotency key reused by command %s", existing.ID)
	}
	// Mark the result in progress BEFORE dispatching: the agent fetches the
	// file right away, and FetchContent only serves devices with a deployment
	// in progress.
	if _, err := d.pool.Exec(ctx, `
		UPDATE software_deployment_results SET status = 'in_progress', command_id = $2,
		       started_at = coalesce(started_at, now()), updated_at = now()
		WHERE id = $1`, x.id, cmdID); err != nil {
		return err
	}
	msg := &aegisonev1.ServerMessage{Payload: &aegisonev1.ServerMessage_Command{Command: &aegisonev1.Command{
		CommandId: cmdID, Type: cmdType, Payload: payload, Signature: sig,
	}}}
	if err := d.disp.Dispatch(x.deviceID, msg); err != nil {
		if mErr := d.cmds.MarkFailed(ctx, cmdID, err.Error()); mErr != nil {
			d.log.Error("software deploy: mark command failed", "command_id", cmdID, "error", mErr.Error())
		}
		// Back to queued; the next tick sends a fresh command.
		if _, uErr := d.pool.Exec(ctx, `
			UPDATE software_deployment_results SET status = 'queued', command_id = NULL, updated_at = now()
			WHERE id = $1`, x.id); uErr != nil {
			return uErr
		}
		d.log.Info("software deploy: dispatch failed, will retry", "result_id", x.id, "error", err.Error())
		return nil
	}
	if err := d.cmds.MarkDispatched(ctx, cmdID); err != nil {
		d.log.Error("software deploy: mark command dispatched", "command_id", cmdID, "error", err.Error())
	}
	d.log.Info("software deploy: command sent", "result_id", x.id, "device_id", x.deviceID,
		"package", x.pkg.Name+" "+x.pkg.Version, "action", action, "command_id", cmdID)
	return nil
}

// finish closes a result and, when it was the deployment's last open one, the
// deployment.
func (d *Deployer) finish(ctx context.Context, x result, status, reason string, res *agentResult) error {
	var outcome *string
	var exitCode *int32
	var reboot *bool
	if res != nil {
		if res.Phase != "" {
			o := strings.TrimPrefix(res.Phase, "ACTION_PHASE_")
			outcome = &o
		}
		exitCode, reboot = res.ExitCode, res.RebootRequired
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, `
		UPDATE software_deployment_results
		SET status = $2, error_message = NULLIF($3, ''), outcome = $4, exit_code = $5, reboot_required = $6,
		    progress_pct = 100, completed_at = now(), updated_at = now()
		WHERE id = $1 AND status IN ('queued', 'in_progress')`, x.id, status, reason, outcome, exitCode, reboot); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE software_deployments SET completed_at = now(), status = CASE
			WHEN EXISTS (SELECT 1 FROM software_deployment_results WHERE deployment_id = $1 AND status = 'failed') THEN 'failed'
			ELSE 'completed' END
		WHERE id = $1 AND status = 'running'
		  AND NOT EXISTS (SELECT 1 FROM software_deployment_results WHERE deployment_id = $1 AND status IN ('queued', 'in_progress'))`,
		x.deploymentID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	d.log.Info("software deploy: finished", "result_id", x.id, "device_id", x.deviceID,
		"package", x.pkg.Name+" "+x.pkg.Version, "status", status, "outcome", deref(outcome), "reason", reason)
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
