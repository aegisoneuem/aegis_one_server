package patchdeploy

// Integration test against a throwaway database with all migrations applied:
//
//	AEGIS_TEST_DATABASE_URL=postgres://aegis_server:...@localhost:5433/postgres go test ./internal/patchdeploy/
//
// Skipped when the variable is unset. Creates its own rows, deletes nothing.
// The agent is a fake: nothing is installed or rebooted anywhere.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/commands"
	"aegis-one/internal/patchcontent"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type fakeDisp struct {
	mu   sync.Mutex
	sent []*aegisonev1.Command
}

func (f *fakeDisp) Dispatch(_ string, msg *aegisonev1.ServerMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, msg.GetCommand())
	return nil
}
func (f *fakeDisp) Connected(string) bool { return true }
func (f *fakeDisp) last() *aegisonev1.Command {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return nil
	}
	return f.sent[len(f.sent)-1]
}
func (f *fakeDisp) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func rnd() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type env struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	d        *Deployer
	disp     *fakeDisp
	cmds     *commands.Store
	clientID string
}

func newEnv(t *testing.T) *env {
	url := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cmds := commands.New(pool)
	keyID, err := cmds.ResolveSigningKey(ctx, key, "pd-test-"+rnd())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, ctx: ctx, pool: pool, disp: &fakeDisp{}, cmds: cmds}
	if err := pool.QueryRow(ctx, `INSERT INTO api_clients (name, role_id) SELECT 'pd-test-'||$1, id FROM roles WHERE name = 'admin' RETURNING id`,
		rnd()).Scan(&e.clientID); err != nil {
		t.Fatal(err)
	}
	e.d = New(pool, patchcontent.New(pool, t.TempDir(), log), cmds, e.disp, key, keyID, log)
	return e
}

// device makes a device + agent missing a fresh KB whose single file is
// already downloaded on the server. Returns the device_id, agent UUID and KB.
func (e *env) device() (deviceID, agentUUID, kb string) {
	ctx, t := e.ctx, e.t
	r := rnd()
	deviceID = "dev-" + r
	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	kb = "KB" + strconv.FormatInt(6000000+n.Int64(), 10)
	var devUUID, patchID string
	must(t, e.pool.QueryRow(ctx, `INSERT INTO devices (hostname, os_family, agent_reported_id, architecture) VALUES ('PC-PD', 'windows', $1, 'x64') RETURNING id`,
		deviceID).Scan(&devUUID))
	must(t, e.pool.QueryRow(ctx, `INSERT INTO agents (device_id, agent_version, install_method) VALUES ($1, '1.0', 'unknown') RETURNING id`,
		devUUID).Scan(&agentUUID))
	must(t, e.pool.QueryRow(ctx, `
		INSERT INTO patch_catalog (vendor, product, kb_or_advisory_id, title) VALUES ('microsoft', 'Windows', $1, 'test')
		ON CONFLICT (vendor, kb_or_advisory_id) DO UPDATE SET title = 'test' RETURNING id`, kb).Scan(&patchID))
	updateID := "u-" + r
	digest := "d-" + r
	file := "windows11.0-" + strings.ToLower(kb) + "-x64_" + r + ".msu"
	exec(t, e, `INSERT INTO wu_update_files (update_id, file_digest, file_name, url) VALUES ($1, $2, $3, 'https://catalog.s.download.windowsupdate.com/c/x.msu')`,
		updateID, digest, file)
	exec(t, e, `INSERT INTO patch_content (file_digest, file_name, url, state, sha256_hash, size_bytes, stored_name, ready_at)
		VALUES ($1, $2, 'https://catalog.s.download.windowsupdate.com/c/x.msu', 'ready', $3, 10, 'x', now())`, digest, file, "sha-"+r)
	exec(t, e, `INSERT INTO device_patch_state (device_id, patch_id, state, detection_source, vendor_update_id) VALUES ($1, $2, 'missing', 'agent_wua', $3)`,
		devUUID, patchID, updateID)
	return deviceID, agentUUID, kb
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func exec(t *testing.T, e *env, sql string, args ...any) {
	t.Helper()
	if _, err := e.pool.Exec(e.ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

// answer is the agent reporting on its last command.
func (e *env) answer(agentUUID, actionType string, phase aegisonev1.ActionPhase, reason string, reboot bool) *aegisonev1.Command {
	cmd := e.disp.last()
	if _, err := e.cmds.ApplyActionStatus(e.ctx, agentUUID, &aegisonev1.ActionStatus{ActionId: cmd.GetCommandId(),
		ActionType: actionType, Phase: phase, Reason: reason, RebootRequired: reboot}); err != nil {
		e.t.Fatal(err)
	}
	return cmd
}

func (e *env) advance() {
	e.t.Helper()
	if err := e.d.advanceAll(e.ctx); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) result(id string) (status, step string, outcome, errMsg *string) {
	must(e.t, e.pool.QueryRow(e.ctx, `SELECT status, COALESCE(step, ''), reboot_outcome, error_message FROM patch_deployment_results WHERE id = $1`, id).
		Scan(&status, &step, &outcome, &errMsg))
	return
}

func TestRebootIfRequiredDB(t *testing.T) {
	e := newEnv(t)
	dev, agent, kb := e.device()
	delay := 60
	out, err := e.d.Create(e.ctx, Request{DeviceID: dev, KB: kb, ClientID: e.clientID, ClientName: "t", Reboot: "if_required", RebootDelaySeconds: &delay})
	if err != nil {
		t.Fatal(err)
	}
	e.advance() // -> stage_patch
	if c := e.disp.last(); c.GetType() != "stage_patch" {
		t.Fatalf("first command %q", c.GetType())
	}
	e.answer(agent, "stage", aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, "patch staged in cache", false)
	e.advance() // -> install_patch
	if c := e.disp.last(); c.GetType() != "install_patch" {
		t.Fatalf("second command %q", c.GetType())
	}
	e.answer(agent, "patch_install", aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, "installed", true)
	e.advance() // -> rebooting
	if _, step, _, _ := e.result(out.ResultID); step != "rebooting" {
		t.Fatalf("step after install = %q, want rebooting", step)
	}
	e.advance() // -> reboot command
	c := e.disp.last()
	if c.GetType() != "reboot" {
		t.Fatalf("third command %q, want reboot", c.GetType())
	}
	var spec aegisonev1.RebootSpec
	must(t, proto.Unmarshal(c.GetPayload(), &spec))
	if spec.DelaySeconds != 60 || !strings.Contains(spec.Message, "in 1 minute(s)") {
		t.Errorf("reboot spec %+v", &spec)
	}
	if st, _, _, _ := e.result(out.ResultID); st != "in_progress" {
		t.Errorf("finished before the reboot answer: %s", st)
	}
	e.answer(agent, "reboot", aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, "reboot scheduled in 60s", false)
	e.advance()
	st, _, outcome, _ := e.result(out.ResultID)
	if st != "succeeded" || outcome == nil || *outcome != "reboot scheduled: reboot scheduled in 60s" {
		t.Errorf("after reboot: status %s outcome %v", st, deref(outcome))
	}
	var rebootCmd *string
	must(t, e.pool.QueryRow(e.ctx, `SELECT reboot_command_id::text FROM patch_deployment_results WHERE id = $1`, out.ResultID).Scan(&rebootCmd))
	if deref(rebootCmd) != c.GetCommandId() {
		t.Errorf("reboot_command_id %v, want %s", deref(rebootCmd), c.GetCommandId())
	}
}

func TestNoRebootWhenNotRequiredDB(t *testing.T) {
	e := newEnv(t)
	dev, agent, kb := e.device()
	out, err := e.d.Create(e.ctx, Request{DeviceID: dev, KB: kb, ClientID: e.clientID, ClientName: "t", Reboot: "if_required"})
	if err != nil {
		t.Fatal(err)
	}
	e.advance()
	e.answer(agent, "stage", aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, "", false)
	e.advance()
	e.answer(agent, "patch_install", aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, "installed", false)
	e.advance()
	st, _, outcome, _ := e.result(out.ResultID)
	if st != "succeeded" || outcome != nil || e.disp.count() != 2 {
		t.Errorf("status %s outcome %v commands %d", st, deref(outcome), e.disp.count())
	}

	// reboot=always reboots even then; the agent's reboot_policy=never answer is recorded.
	dev2, agent2, kb2 := e.device()
	out2, err := e.d.Create(e.ctx, Request{DeviceID: dev2, KB: kb2, ClientID: e.clientID, ClientName: "t", Reboot: "always"})
	if err != nil {
		t.Fatal(err)
	}
	e.advance()
	e.answer(agent2, "stage", aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, "", false)
	e.advance()
	e.answer(agent2, "patch_install", aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, "installed", false)
	e.advance()
	e.advance()
	if c := e.disp.last(); c.GetType() != "reboot" {
		t.Fatalf("always: last command %q", c.GetType())
	}
	e.answer(agent2, "reboot", aegisonev1.ActionPhase_ACTION_PHASE_NOT_APPLICABLE, "reboot blocked by agent policy (reboot_policy=never)", false)
	e.advance()
	st, _, outcome, _ = e.result(out2.ResultID)
	if st != "succeeded" || !strings.HasPrefix(deref(outcome), "not rebooted: reboot blocked") {
		t.Errorf("always: status %s outcome %v", st, deref(outcome))
	}
}

func TestStageOnlyDB(t *testing.T) {
	e := newEnv(t)
	dev, agent, kb := e.device()
	out, err := e.d.Create(e.ctx, Request{DeviceID: dev, KB: kb, ClientID: e.clientID, ClientName: "t", StageOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !out.StageOnly || out.Reboot != "no_reboot" {
		t.Errorf("created %+v", out)
	}
	e.advance()
	e.answer(agent, "stage", aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, "patch staged in cache", false)
	e.advance()
	st, _, _, _ := e.result(out.ResultID)
	var staged bool
	must(t, e.pool.QueryRow(e.ctx, `SELECT (file_results->0->>'staged')::boolean FROM patch_deployment_results WHERE id = $1`, out.ResultID).Scan(&staged))
	if st != "succeeded" || !staged || e.disp.count() != 1 {
		t.Errorf("stage only: status %s staged %v commands %d", st, staged, e.disp.count())
	}
	// Now the real push: stage again (the agent answers "already staged"), then install.
	out2, err := e.d.Create(e.ctx, Request{DeviceID: dev, KB: kb, ClientID: e.clientID, ClientName: "t"})
	if err != nil {
		t.Fatal(err)
	}
	e.advance()
	e.answer(agent, "stage", aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, "already staged", false)
	e.advance()
	if c := e.disp.last(); c.GetType() != "install_patch" {
		t.Errorf("after stage-only, push sent %q", c.GetType())
	}
	_ = out2
	if _, err := e.d.Create(e.ctx, Request{DeviceID: dev, KB: kb, StageOnly: true, Reboot: "always"}); err == nil {
		t.Error("stage only with a reboot accepted")
	}
}

func TestMaintenanceDeferralDB(t *testing.T) {
	e := newEnv(t)
	dev, agent, kb := e.device()
	out, err := e.d.Create(e.ctx, Request{DeviceID: dev, KB: kb, ClientID: e.clientID, ClientName: "t"})
	if err != nil {
		t.Fatal(err)
	}
	e.advance()
	cmd := e.answer(agent, "stage", aegisonev1.ActionPhase_ACTION_PHASE_QUEUED, "deferred to maintenance window", false)
	// 7 hours later: past the 6h timeout, but the agent said it waits for its window.
	exec(t, e, `UPDATE agent_commands SET dispatched_at = now() - interval '7 hours', last_status_at = now() - interval '7 hours' WHERE id = $1`, cmd.GetCommandId())
	e.advance()
	if st, step, _, _ := e.result(out.ResultID); st != "in_progress" || step != "staging" {
		t.Fatalf("deferred step failed early: %s / %s", st, step)
	}
	// The window opens and the agent works on it: a fresh status restarts the clock.
	e.answer(agent, "stage", aegisonev1.ActionPhase_ACTION_PHASE_DOWNLOADING, "fetching patch for staging", false)
	exec(t, e, `UPDATE agent_commands SET dispatched_at = now() - interval '8 days' WHERE id = $1`, cmd.GetCommandId())
	e.advance()
	if st, _, _, _ := e.result(out.ResultID); st != "in_progress" {
		t.Fatalf("recent status ignored: %s", st)
	}
	// Then silence for 7 hours: that does time out.
	exec(t, e, `UPDATE agent_commands SET last_status_at = now() - interval '7 hours' WHERE id = $1`, cmd.GetCommandId())
	e.advance()
	if st, _, _, msg := e.result(out.ResultID); st != "failed" || !strings.Contains(deref(msg), "no final answer to stage_patch") {
		t.Errorf("silent step: %s %v", st, deref(msg))
	}
}

func TestStepTimedOut(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	q, run := "ACTION_PHASE_QUEUED", "ACTION_PHASE_RUNNING"
	win, other := "deferred to maintenance window", "queued"
	cases := []struct {
		at     *time.Time
		phase  *string
		reason *string
		want   bool
	}{
		{nil, nil, nil, false},
		{ago(5 * time.Hour), nil, nil, false},
		{ago(7 * time.Hour), nil, nil, true},
		{ago(7 * time.Hour), &q, &win, false},
		{ago(13 * 24 * time.Hour), &q, &win, false},
		{ago(15 * 24 * time.Hour), &q, &win, true},
		{ago(7 * time.Hour), &q, &other, true},
		{ago(7 * time.Hour), &run, &win, true},
	}
	for i, c := range cases {
		if got := stepTimedOut(c.at, c.phase, c.reason, now); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

func TestRebootOptions(t *testing.T) {
	n := func(v int) *int { return &v }
	ok := []Request{{}, {Reboot: "if_required"}, {Reboot: "always", RebootDelaySeconds: n(0), RebootMessage: "bye"}, {StageOnly: true}}
	for _, r := range ok {
		if _, _, _, err := r.rebootOptions(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	bad := []Request{{Reboot: "later"}, {RebootDelaySeconds: n(60)}, {Reboot: "always", RebootDelaySeconds: n(90000)},
		{Reboot: "always", StageOnly: true}, {Reboot: "always", RebootMessage: "a\nb"}, {Reboot: "always", RebootMessage: strings.Repeat("x", 401)}}
	for _, r := range bad {
		if _, _, _, err := r.rebootOptions(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	if b, d, _, _ := (Request{Reboot: "IF_REQUIRED"}).rebootOptions(); b != "if_required" || d == nil || *d != DefaultRebootDelay {
		t.Errorf("default delay: %s %v", b, d)
	}
	for delay, want := range map[int]string{0: "restart now", 45: "in 45 second(s)", 900: "in 15 minute(s)", 7200: "in 2 hour(s)"} {
		if m := rebootMessage(nil, delay); !strings.Contains(m, want) {
			t.Errorf("delay %d: %q", delay, m)
		}
	}
	custom := "Patch night"
	if m := rebootMessage(&custom, 60); m != custom {
		t.Errorf("custom message: %q", m)
	}
}
