package softwaredist

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
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
	// maxPlan caps a package plus its dependencies (the agent team's limit).
	maxPlan = 64
	// answerGrace is added to the package's own timeout (default 30 minutes on
	// the agent) before a dispatched command with no final answer is failed:
	// the fetch, the install queue and an agent restart all take time.
	answerGrace = 6 * time.Hour
	// agentDefaultTimeout is the agent's per-install limit when the package sets none.
	agentDefaultTimeout = 30 * time.Minute
	// secretTTL is how long a deployment's password / secure parameters stay in
	// server memory waiting for offline devices.
	secretTTL = 24 * time.Hour
	// sensitive is what the audit trail shows instead of secrets (the agent's
	// own audit summary uses the same literal).
	sensitive = "<sensitive — secure parameters in use>"
)

type Dispatcher interface {
	Dispatch(deviceID string, msg *aegisonev1.ServerMessage) error
	Connected(deviceID string) bool
}

type Deployer struct {
	pool    *pgxpool.Pool
	pkgs    *Store
	cmds    *commands.Store
	disp    Dispatcher
	key     ed25519.PrivateKey
	keyID   string
	log     *slog.Logger
	wake    chan struct{}
	secrets *secretStore
}

func NewDeployer(pool *pgxpool.Pool, pkgs *Store, cmds *commands.Store, disp Dispatcher,
	key ed25519.PrivateKey, keyID string, log *slog.Logger) *Deployer {
	return &Deployer{pool: pool, pkgs: pkgs, cmds: cmds, disp: disp, key: key, keyID: keyID, log: log,
		wake: make(chan struct{}, 1), secrets: &secretStore{m: map[string]*secretEntry{}}}
}

// secretStore keeps each private deployment's password and secure parameters
// in memory only - never in the database or logs. A server restart loses
// them; the deployment's unsent results then fail with a clear reason.
type secretStore struct {
	mu sync.Mutex
	m  map[string]*secretEntry
}

type secretEntry struct {
	password []byte
	params   map[string]string
	expires  time.Time
}

func (s *secretStore) put(id string, password string, params map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = &secretEntry{password: []byte(password), params: params, expires: time.Now().Add(secretTTL)}
}

func (s *secretStore) get(id string) (*secretEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e, true
}

func (s *secretStore) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[id]; ok {
		for i := range e.password {
			e.password[i] = 0
		}
		delete(s.m, id)
	}
}

func (s *secretStore) sweep() {
	s.mu.Lock()
	var expired []string
	for id, e := range s.m {
		if time.Now().After(e.expires) {
			expired = append(expired, id)
		}
	}
	s.mu.Unlock()
	for _, id := range expired {
		s.drop(id)
	}
}

type DeployRequest struct {
	PackageID  string
	Action     string   // install | uninstall
	DeviceIDs  []string // agent-reported device ids
	ClientID   string
	ClientName string
	CanScript  bool // caller holds software.script
	CanRunAs   bool // caller holds software.runas

	Execution              *Execution
	SecureParameters       map[string]string
	MaxFetchBytesPerSecond int64
}

type DeployCreated struct {
	DeploymentID string   `json:"deployment_id"`
	PackageID    string   `json:"package_id"`
	Package      string   `json:"package"`
	Action       string   `json:"action"`
	Devices      int      `json:"devices"`
	Plan         []string `json:"plan"` // packages in install order (dependencies first)
}

// Create queues a deployment of one package (and, for an install, the
// packages it requires, dependencies first) to a list of devices. Devices
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
	if req.MaxFetchBytesPerSecond < 0 {
		return nil, userErr("max_fetch_bytes_per_second must be positive (or omitted)")
	}
	pkg, err := d.pkgs.Get(ctx, req.PackageID)
	if err != nil {
		return nil, err
	}
	if pkg == nil {
		return nil, userErr("unknown package_id %q", req.PackageID)
	}
	if action == "uninstall" && pkg.InstallerType == "inf" {
		return nil, userErr("driver (inf) packages can't be uninstalled through software_deploy")
	}

	// Dependencies are install-only: an uninstall touches just the package.
	plan := []*Package{pkg}
	if action == "install" {
		if plan, err = d.plan(ctx, pkg); err != nil {
			return nil, err
		}
	}
	for _, p := range plan {
		if p.NeedsScriptPerm() && !req.CanScript {
			return nil, &PermissionError{fmt.Sprintf("%s %s runs a script, bundle command or steps: that needs the software.script permission", p.Name, p.Version)}
		}
	}

	exec := req.Execution
	if exec == nil {
		exec = &Execution{}
	}
	if err := exec.validate(); err != nil {
		return nil, err
	}
	private := exec.Mode != "system" || len(req.SecureParameters) > 0
	if private && !req.CanRunAs {
		return nil, &PermissionError{"running as a user or account, or passing secure parameters, needs the software.runas permission"}
	}
	if err := validateSecrets(req.SecureParameters, exec.Password, pkg.Parameters, pkg.publicText()); err != nil {
		return nil, err
	}
	if pkg.Detection.usesHKCU() && exec.Mode == "system" {
		return nil, userErr("HKCU detection rules need execution mode logged_in_user or specified_account (with detection_scope user)")
	}
	if pkg.Detection.usesHKCU() && exec.Mode == "specified_account" && exec.DetectionScope != "user" {
		return nil, userErr("HKCU detection with a specified account needs detection_scope user")
	}
	hasSecrets := exec.Password != "" || len(req.SecureParameters) > 0
	secretNames := make([]string, 0, len(req.SecureParameters))
	for k := range req.SecureParameters {
		secretNames = append(secretNames, k)
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
	for _, p := range plan {
		out.Plan = append(out.Plan, p.Name+" "+p.Version)
	}
	var sessionID *int64
	if exec.SessionID != nil {
		v := int64(*exec.SessionID)
		sessionID = &v
	}
	var maxFetch *int64
	if req.MaxFetchBytesPerSecond > 0 {
		maxFetch = &req.MaxFetchBytesPerSecond
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if err := tx.QueryRow(ctx, `
		INSERT INTO software_deployments (package_id, action, schedule_type, status, name, created_by_api_client_id,
		                                  execution_mode, session_id, run_as_username, run_as_domain, detection_scope,
		                                  has_secrets, secure_param_names, max_fetch_bytes_per_second)
		VALUES ($1, $2, 'immediate', 'running', $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10, $11, $12)
		RETURNING id`,
		pkg.ID, dbAction, fmt.Sprintf("%s %s %s -> %d device(s)", action, pkg.Name, pkg.Version, len(devices)), req.ClientID,
		exec.Mode, sessionID, exec.Username, exec.Domain, exec.DetectionScope, hasSecrets, secretNames, maxFetch,
	).Scan(&out.DeploymentID); err != nil {
		return nil, fmt.Errorf("insert software_deployments: %w", err)
	}
	ids := make([]string, 0, len(devices))
	for _, dev := range devices {
		ids = append(ids, uuids[dev])
	}
	for order, p := range plan {
		_, err = tx.Exec(ctx, `
			INSERT INTO software_deployment_results (deployment_id, device_id, package_id, status, plan_order)
			SELECT $1, unnest($2::uuid[]), $3, 'queued', $4`, out.DeploymentID, ids, p.ID, order)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.ConstraintName == "uq_sdr_active_device_package" {
			return nil, userErr("%s %s is already being deployed to one of these devices; wait for it to finish", p.Name, p.Version)
		}
		if err != nil {
			return nil, fmt.Errorf("insert software_deployment_results: %w", err)
		}
	}
	auditDetails := map[string]any{
		"deployment_id": out.DeploymentID, "package_id": pkg.ID, "package": out.Package, "action": action,
		"installer_type": pkg.InstallerType, "script": pkg.NeedsScriptPerm(), "sha256": pkg.SHA256,
		"device_ids": devices, "plan": out.Plan, "execution_mode": exec.Mode, "run_as_username": exec.Username,
	}
	if hasSecrets {
		auditDetails["secrets"] = sensitive
		auditDetails["secure_parameter_names"] = secretNames
	}
	details, _ := json.Marshal(auditDetails)
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', $1, $2, 'software.deploy.create', 'software_deployment', $3, $4::jsonb)`,
		req.ClientID, req.ClientName, out.DeploymentID, string(details)); err != nil {
		return nil, fmt.Errorf("insert audit_log: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if hasSecrets {
		d.secrets.put(out.DeploymentID, exec.Password, req.SecureParameters)
	}
	d.log.Info("software deployment created", "deployment_id", out.DeploymentID, "package_id", pkg.ID,
		"package", out.Package, "action", action, "devices", len(devices), "plan", len(plan), "execution_mode", exec.Mode,
		"private", private)
	d.kick()
	return out, nil
}

// plan returns root's install order: every package it (transitively)
// requires, dependencies first, each once. Cycles and missing packages are
// refused.
func (d *Deployer) plan(ctx context.Context, root *Package) ([]*Package, error) {
	var order []*Package
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(p *Package, path []string) error
	visit = func(p *Package, path []string) error {
		switch state[p.ID] {
		case 1:
			return userErr("dependency cycle: %s -> %s", strings.Join(path, " -> "), p.Name)
		case 2:
			return nil
		}
		state[p.ID] = 1
		for _, id := range p.Requires {
			dep, err := d.pkgs.Get(ctx, id)
			if err != nil {
				return err
			}
			if dep == nil {
				return userErr("%s requires package %s, which no longer exists", p.Name, id)
			}
			if err := visit(dep, append(path, p.Name)); err != nil {
				return err
			}
		}
		state[p.ID] = 2
		order = append(order, p)
		if len(order) > maxPlan {
			return userErr("more than %d packages in the dependency plan", maxPlan)
		}
		return nil
	}
	if err := visit(root, nil); err != nil {
		return nil, err
	}
	return order, nil
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
// so a restart resumes (except private deployments, whose secrets were only in
// memory); it assumes a single server instance.
func (d *Deployer) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		d.secrets.sweep()
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
	rootPackageID                                       string
	planOrder                                           int
	clientID                                            *string
	pkg                                                 *Package
	commandID, cmdStatus, cmdType                       *string
	cmdAt                                               *time.Time
	cmdResult                                           []byte
	exec                                                Execution
	hasSecrets                                          bool
	secretNames                                         []string
	maxFetch                                            *int64
	// earlier packages of the plan on the same device
	depPending int
	depFailed  *string // name of a failed dependency
	depReboot  *string // name of a dependency that needs a reboot
}

func (d *Deployer) advanceAll(ctx context.Context) error {
	rows, err := d.pool.Query(ctx, `
		SELECT r.id, r.deployment_id, dv.agent_reported_id, coalesce(a.id::text, ''), r.status, sd.action, sd.package_id::text,
		       r.plan_order, sd.created_by_api_client_id::text, r.command_id::text, c.status, r.command_type,
		       coalesce(c.dispatched_at, c.issued_at), c.result,
		       sd.execution_mode, sd.session_id, coalesce(sd.run_as_username, ''), coalesce(sd.run_as_domain, ''),
		       coalesce(sd.detection_scope, ''), sd.has_secrets, sd.secure_param_names, sd.max_fetch_bytes_per_second,
		       (SELECT count(*) FROM software_deployment_results e
		        WHERE e.deployment_id = r.deployment_id AND e.device_id = r.device_id AND e.plan_order < r.plan_order
		          AND e.status <> 'succeeded'),
		       (SELECT min(ep.name) FROM software_deployment_results e JOIN software_packages ep ON ep.id = e.package_id
		        WHERE e.deployment_id = r.deployment_id AND e.device_id = r.device_id AND e.plan_order < r.plan_order
		          AND e.status = 'failed'),
		       (SELECT min(ep.name) FROM software_deployment_results e JOIN software_packages ep ON ep.id = e.package_id
		        WHERE e.deployment_id = r.deployment_id AND e.device_id = r.device_id AND e.plan_order < r.plan_order
		          AND e.reboot_required),
		       `+PackageColumnsP+`
		FROM software_deployment_results r
		JOIN software_deployments sd ON sd.id = r.deployment_id
		JOIN software_packages p ON p.id = r.package_id
		JOIN devices dv ON dv.id = r.device_id
		LEFT JOIN agents a ON a.device_id = dv.id AND a.revoked_at IS NULL
		LEFT JOIN agent_commands c ON c.id = r.command_id
		WHERE r.status IN ('queued', 'in_progress')
		ORDER BY r.plan_order, r.updated_at LIMIT 1000`)
	if err != nil {
		return err
	}
	var active []result
	for rows.Next() {
		var x result
		var sessionID *int64
		head := []any{&x.id, &x.deploymentID, &x.deviceID, &x.agentID, &x.status, &x.action, &x.rootPackageID,
			&x.planOrder, &x.clientID, &x.commandID, &x.cmdStatus, &x.cmdType, &x.cmdAt, &x.cmdResult,
			&x.exec.Mode, &sessionID, &x.exec.Username, &x.exec.Domain, &x.exec.DetectionScope, &x.hasSecrets,
			&x.secretNames, &x.maxFetch, &x.depPending, &x.depFailed, &x.depReboot}
		p, err := scanPackage(prefixRow{rows, head})
		if err != nil {
			rows.Close()
			return err
		}
		if sessionID != nil {
			v := uint32(*sessionID)
			x.exec.SessionID = &v
		}
		x.pkg = p
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

// prefixRow scans head columns before the package columns of one row.
type prefixRow struct {
	row  interface{ Scan(...any) error }
	head []any
}

func (r prefixRow) Scan(dest ...any) error { return r.row.Scan(append(r.head, dest...)...) }

func (d *Deployer) advance(ctx context.Context, x result) error {
	if x.agentID == "" {
		return d.finish(ctx, x, "failed", "the device's agent was revoked", nil)
	}
	if x.status == "queued" || x.commandID == nil {
		switch {
		case x.depFailed != nil:
			return d.finish(ctx, x, "failed", "dependency "+*x.depFailed+" failed on this device", nil)
		case x.depReboot != nil:
			return d.finish(ctx, x, "failed", "blocked: dependency "+*x.depReboot+" needs a reboot first; reboot the device and deploy again", nil)
		case x.depPending > 0:
			return nil // an earlier package in the plan is still running
		}
		return d.send(ctx, x)
	}
	cmdType := deref(x.cmdType)
	if cmdType == "" {
		cmdType = "software_deploy"
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
		return d.finish(ctx, x, "failed", fmt.Sprintf("%s %s: %s", cmdType, deref(x.cmdStatus), reason), &res)
	}
	limit := agentDefaultTimeout
	if x.pkg.TimeoutSeconds > 0 {
		limit = time.Duration(x.pkg.TimeoutSeconds) * time.Second
	}
	if x.cmdAt != nil && time.Since(*x.cmdAt) > limit+answerGrace {
		return d.finish(ctx, x, "failed", "no final answer to "+cmdType+" from the agent", nil)
	}
	return nil
}

// agentResult is the part of agent_commands.result we show (written by
// commands.ApplyActionStatus / ApplyCommandResult / MarkFailed).
type agentResult struct {
	Phase            string `json:"phase"`
	Reason           string `json:"reason"`
	Detail           string `json:"detail"`
	ExitCode         *int32 `json:"exit_code"`
	RebootRequired   *bool  `json:"reboot_required"`
	Message          string `json:"message"`
	Error            string `json:"error"`
	PackageDirectory string `json:"package_directory"`
	PackageCleanup   string `json:"package_cleanup"`
}

// SpecOptions are the per-deployment parts of a SoftwareDeploySpec.
type SpecOptions struct {
	Execution        *Execution // nil: no execution context sent (SYSTEM)
	Password         []byte
	SecureParameters map[string]string
	MaxFetch         int64
}

// Spec builds the agent's SoftwareDeploySpec for p.
func Spec(p *Package, action string, opt SpecOptions) *aegisonev1.SoftwareDeploySpec {
	s := &aegisonev1.SoftwareDeploySpec{
		PackageId:     p.ID,
		Name:          p.Name,
		Version:       p.Version,
		Action:        action,
		InstallerType: p.InstallerType,
		// Not a real path: the agent takes the extension from it (to name the
		// fetched file so the right program runs it). A file of that exact name
		// in the agent's drop folder would be used instead, but only if it
		// matches expected_hash.
		FilePath:               p.ID + p.Ext(),
		ExpectedHash:           p.SHA256,
		HashAlgorithm:          "sha256",
		SilentArgs:             p.SilentArgs,
		SuccessExitCodes:       p.SuccessExitCodes,
		TimeoutSeconds:         p.TimeoutSeconds,
		ContentId:              p.ID,
		RequireSignature:       p.RequireSignature,
		ProductCode:            p.ProductCode,
		UninstallKey:           p.UninstallKey,
		DisplayName:            p.DisplayName,
		Parameters:             p.Parameters,
		RequireAcPower:         p.RequireACPower,
		CaptureScriptContent:   p.CaptureScriptContent,
		MaxFetchBytesPerSecond: opt.MaxFetch,
		Steps:                  p.Steps.proto(),
		Detection:              p.Detection.proto(),
	}
	if p.Detection != nil {
		s.Version = "" // the agent refuses detection rules mixed with version-based detection
	}
	if p.IsBundle {
		s.Bundle = &aegisonev1.SoftwareBundle{EntryPoint: p.BundleEntryPoint, Command: p.BundleCommand,
			Destination: p.BundleDestination, Cleanup: p.BundleCleanup}
	}
	if opt.Execution != nil {
		s.Execution = &aegisonev1.SoftwareExecution{Mode: opt.Execution.Mode, SessionId: opt.Execution.SessionID,
			Username: opt.Execution.Username, Domain: opt.Execution.Domain, PasswordUtf8: opt.Password,
			DetectionScope: opt.Execution.DetectionScope}
	}
	if len(opt.SecureParameters) > 0 {
		s.SecureParameters = opt.SecureParameters
	}
	return s
}

// send signs and dispatches the package's software_deploy* command. An
// offline device stays queued.
func (d *Deployer) send(ctx context.Context, x result) error {
	if !d.disp.Connected(x.deviceID) {
		return nil
	}
	action := x.action
	if action == "remove" {
		action = "uninstall"
	}
	// Execution and secrets belong to the deployed package only; a dependency
	// runs as SYSTEM without them.
	root := x.pkg.ID == x.rootPackageID
	opt := SpecOptions{}
	if x.maxFetch != nil {
		opt.MaxFetch = *x.maxFetch
	}
	if root && (x.exec.Mode != "system" || x.hasSecrets) {
		e := x.exec
		opt.Execution = &e
	}
	if root && x.hasSecrets {
		sec, ok := d.secrets.get(x.deploymentID)
		if !ok {
			return d.finish(ctx, x, "failed", "this deployment's password / secure parameters are no longer in server memory "+
				"(server restarted or 24 hours passed); create the deployment again", nil)
		}
		opt.Password, opt.SecureParameters = sec.password, sec.params
	}
	spec := Spec(x.pkg, action, opt)
	cmdType := CommandType(spec)
	ok, err := d.cmds.Supports(ctx, x.agentID, cmdType)
	if err != nil {
		return err
	}
	if !ok {
		return d.finish(ctx, x, "failed", "the device's agent does not support "+cmdType+" (update the agent)", nil)
	}
	var attempt int
	if err := d.pool.QueryRow(ctx, `
		UPDATE software_deployment_results SET attempt_count = attempt_count + 1, command_type = $2, updated_at = now()
		WHERE id = $1 RETURNING attempt_count`, x.id, cmdType).Scan(&attempt); err != nil {
		return err
	}
	payload, err := proto.Marshal(spec)
	if err != nil {
		return err
	}
	id, err := commands.NewID()
	if err != nil {
		return err
	}
	sig := signing.SignCommand(d.key, cmdType, id, payload)
	audit := map[string]any{
		"package_id": spec.PackageId, "name": x.pkg.Name, "version": x.pkg.Version, "action": spec.Action,
		"installer_type": spec.InstallerType, "expected_hash": spec.ExpectedHash, "silent_args": spec.SilentArgs,
		"product_code": spec.ProductCode, "uninstall_key": spec.UninstallKey, "display_name": spec.DisplayName,
		"require_signature": spec.RequireSignature, "software_deployment_id": x.deploymentID,
		"bundle": x.pkg.IsBundle, "has_steps": spec.Steps != nil, "has_detection": spec.Detection != nil,
		"parameters": spec.Parameters, "require_ac_power": spec.RequireAcPower,
	}
	if opt.Execution != nil {
		audit["execution_mode"], audit["run_as_username"] = opt.Execution.Mode, opt.Execution.Username
	}
	if len(opt.Password) > 0 || len(opt.SecureParameters) > 0 {
		audit["secrets"] = sensitive
		audit["secure_parameter_names"] = x.secretNames
	}
	cmdID, existing, err := d.cmds.Create(ctx, commands.Issue{
		ID: id, AgentUUID: x.agentID, DeviceID: x.deviceID, Type: cmdType, Payload: audit,
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
	msg := &aegisonev1.ServerMessage{Payload: &aegisonev1.ServerMessage_Command{
		Command: commands.Envelope(cmdID, cmdType, payload, sig, "software_deployment:"+x.deploymentID)}}
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
		"package", x.pkg.Name+" "+x.pkg.Version, "action", action, "command_type", cmdType, "command_id", cmdID)
	return nil
}

// finish closes a result and, when it was the deployment's last open one, the
// deployment (and forgets its secrets).
func (d *Deployer) finish(ctx context.Context, x result, status, reason string, res *agentResult) error {
	var outcome, pkgDir, pkgCleanup *string
	var exitCode *int32
	var reboot *bool
	if res != nil {
		if res.Phase != "" {
			o := strings.TrimPrefix(res.Phase, "ACTION_PHASE_")
			outcome = &o
		}
		exitCode, reboot = res.ExitCode, res.RebootRequired
		if res.PackageDirectory != "" {
			pkgDir = &res.PackageDirectory
		}
		if res.PackageCleanup != "" {
			pkgCleanup = &res.PackageCleanup
		}
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, `
		UPDATE software_deployment_results
		SET status = $2, error_message = NULLIF($3, ''), outcome = $4, exit_code = $5, reboot_required = $6,
		    package_directory = $7, package_cleanup = $8,
		    progress_pct = 100, completed_at = now(), updated_at = now()
		WHERE id = $1 AND status IN ('queued', 'in_progress')`, x.id, status, reason, outcome, exitCode, reboot, pkgDir, pkgCleanup); err != nil {
		return err
	}
	var closed bool
	if err := tx.QueryRow(ctx, `
		WITH upd AS (
			UPDATE software_deployments SET completed_at = now(), status = CASE
				WHEN EXISTS (SELECT 1 FROM software_deployment_results WHERE deployment_id = $1 AND status = 'failed') THEN 'failed'
				ELSE 'completed' END
			WHERE id = $1 AND status = 'running'
			  AND NOT EXISTS (SELECT 1 FROM software_deployment_results
			                  WHERE deployment_id = $1 AND status IN ('queued', 'in_progress') AND id <> $2)
			RETURNING 1)
		SELECT EXISTS (SELECT 1 FROM upd)`, x.deploymentID, x.id).Scan(&closed); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if closed {
		d.secrets.drop(x.deploymentID)
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
