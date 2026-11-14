package agentpolicy

// Integration test against a throwaway database with all migrations applied:
//
//	AEGIS_TEST_DATABASE_URL=postgres://aegis_server:...@localhost:5433/postgres go test ./internal/agentpolicy/
//
// Skipped when the variable is unset. It creates its own rows and deletes
// nothing. Agent policies are fleet-wide, so it only compares versions it
// published itself.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/commands"
	"aegis-one/internal/identity"
	"aegis-one/internal/signing"

	"github.com/jackc/pgx/v5/pgxpool"
)

type fakeAgents struct {
	mu   sync.Mutex
	sent map[string][]*aegisonev1.Command
	up   map[string]bool
}

func (f *fakeAgents) Dispatch(dev string, msg *aegisonev1.ServerMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent[dev] = append(f.sent[dev], msg.GetCommand())
	return nil
}
func (f *fakeAgents) Connected(dev string) bool { return f.up[dev] }
func (f *fakeAgents) ConnectedDevices() []string {
	var out []string
	for d, ok := range f.up {
		if ok {
			out = append(out, d)
		}
	}
	return out
}
func (f *fakeAgents) last(dev string) *aegisonev1.Command {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sent[dev]
	if len(s) == 0 {
		return nil
	}
	return s[len(s)-1]
}
func (f *fakeAgents) count(dev string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent[dev])
}

func rnd() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func TestPolicyPushDB(t *testing.T) {
	url := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cmdStore := commands.New(pool)
	keyID, err := cmdStore.ResolveSigningKey(ctx, key, "test-"+rnd())
	if err != nil {
		t.Fatal(err)
	}
	var clientID string
	if err := pool.QueryRow(ctx, `INSERT INTO api_clients (name, role_id) SELECT 'policy-test-'||$1, id FROM roles WHERE name = 'admin' RETURNING id`,
		rnd()).Scan(&clientID); err != nil {
		t.Fatal(err)
	}
	k := &identity.Known{DeviceID: "dev-" + rnd()}
	pool.QueryRow(ctx, `INSERT INTO devices (hostname, os_family, agent_reported_id) VALUES ('PC-POL', 'windows', $1) RETURNING id`, k.DeviceID).Scan(&k.DeviceUUID)
	pool.QueryRow(ctx, `INSERT INTO agents (device_id, agent_version, install_method) VALUES ($1, '1.0', 'unknown') RETURNING id`, k.DeviceUUID).Scan(&k.AgentUUID)
	// The agent advertises capabilities but not set_policy (agent 2026-11-12): it must still be sent.
	pool.Exec(ctx, `UPDATE agents SET agent_capabilities = ARRAY['install_patch'] WHERE id = $1`, k.AgentUUID)

	agents := &fakeAgents{sent: map[string][]*aegisonev1.Command{}, up: map[string]bool{k.DeviceID: true}}
	store := NewStore(pool)
	p := NewPusher(ctx, pool, store, &commands.Sender{Store: cmdStore, Disp: agents, Key: key, KeyID: keyID}, agents, log)
	status := func() (string, int64) {
		var s string
		var at int64
		pool.QueryRow(ctx, `SELECT status, issued_at FROM agent_policy_state WHERE agent_id = $1`, k.AgentUUID).Scan(&s, &at)
		return s, at
	}
	answer := func(cmd *aegisonev1.Command, phase aegisonev1.ActionPhase) {
		st := &aegisonev1.ActionStatus{ActionId: cmd.GetCommandId(), ActionType: "set_policy", Phase: phase}
		cmdStore.ApplyActionStatus(ctx, k.AgentUUID, st)
		p.ActionStatus(ctx, k, st)
	}

	// Publish twice in the same second: issued_at still strictly increases.
	d1, _ := ParseRequest([]byte(`{"modules":{"deny":["open_shell"]}}`))
	v1, err := store.Publish(ctx, d1, "first", clientID, "policy-test")
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := ParseRequest([]byte(`{"modules":{"deny":["open_shell","run_command"]},"patch":{"reboot_policy":"never"}}`))
	v2, err := store.Publish(ctx, d2, "", clientID, "policy-test")
	if err != nil {
		t.Fatal(err)
	}
	if v2.IssuedAt <= v1.IssuedAt {
		t.Fatalf("issued_at %d then %d", v1.IssuedAt, v2.IssuedAt)
	}

	// Connect: the current version is sent, signed over the exact stored bytes.
	p.Connected(ctx, k)
	cmd := agents.last(k.DeviceID)
	if cmd == nil || cmd.GetType() != "set_policy" || string(cmd.GetPayload()) != string(v2.Wire) {
		t.Fatalf("pushed %+v", cmd)
	}
	if !signing.VerifyCommand(pub, cmd.GetType(), cmd.GetCommandId(), cmd.GetPayload(), cmd.GetSignature()) {
		t.Error("signature does not verify")
	}
	var wire map[string]any
	json.Unmarshal(cmd.GetPayload(), &wire)
	if wire["version"] != float64(1) || wire["policy_id"] != v2.ID || wire["issued_at"] != float64(v2.IssuedAt) {
		t.Errorf("wire header: %v", wire)
	}
	if s, at := status(); s != "pending" || at != v2.IssuedAt {
		t.Errorf("after push: %s %d", s, at)
	}

	// No answer yet (agent reconnected): pushed again.
	p.Connected(ctx, k)
	if agents.count(k.DeviceID) != 2 {
		t.Errorf("pending not re-pushed: %d sends", agents.count(k.DeviceID))
	}
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS)
	if s, _ := status(); s != "applied" {
		t.Errorf("after SUCCESS: %s", s)
	}
	// Applied: a reconnect sends nothing.
	if st, _ := p.Push(ctx, k.DeviceID); st != "up_to_date" || agents.count(k.DeviceID) != 2 {
		t.Errorf("applied agent pushed again: %s, %d sends", st, agents.count(k.DeviceID))
	}

	// Tamper report: alert opened, state tampered, current version sent again.
	p.AuditEvent(ctx, k, &aegisonev1.AuditEvent{EventType: "policy_tampered", Reason: "policy file signature invalid"})
	if agents.count(k.DeviceID) != 3 {
		t.Fatalf("no re-push after tamper: %d sends", agents.count(k.DeviceID))
	}
	var alertStatus, severity string
	var occ int
	pool.QueryRow(ctx, `SELECT status, severity, occurrence_count FROM alerts WHERE dedup_key = $1`, alertKey(k.DeviceUUID)).Scan(&alertStatus, &severity, &occ)
	if alertStatus != "open" || severity != "high" {
		t.Errorf("alert: %s %s", alertStatus, severity)
	}
	p.AuditEvent(ctx, k, &aegisonev1.AuditEvent{EventType: "policy_lockdown"})
	pool.QueryRow(ctx, `SELECT severity, occurrence_count FROM alerts WHERE dedup_key = $1 AND status = 'open'`, alertKey(k.DeviceUUID)).Scan(&severity, &occ)
	if severity != "critical" || occ != 2 {
		t.Errorf("repeat alert: %s x%d", severity, occ)
	}
	// Agent in safe mode re-applies the same version: alert stays open for an
	// admin, with the recovery noted.
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS)
	var reapplied bool
	pool.QueryRow(ctx, `SELECT status, details ? 'policy_reapplied_at' FROM alerts WHERE dedup_key = $1 ORDER BY last_seen_at DESC LIMIT 1`,
		alertKey(k.DeviceUUID)).Scan(&alertStatus, &reapplied)
	if s, _ := status(); s != "applied" || alertStatus != "open" || !reapplied {
		t.Errorf("after re-apply: state %s, alert %s, reapplied noted %v", s, alertStatus, reapplied)
	}

	// A late answer to the v2 push must not mark a newer v3 applied.
	oldCmd := agents.last(k.DeviceID)
	d3, _ := ParseRequest([]byte(`{"logging":{"level":"warn"}}`))
	v3, _ := store.Publish(ctx, d3, "", clientID, "policy-test")
	if counts := p.Broadcast(ctx); counts["dispatched"] < 1 {
		t.Errorf("broadcast: %v", counts)
	}
	answer(oldCmd, aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS)
	if s, at := status(); s != "pending" || at != v3.IssuedAt {
		t.Errorf("stale answer changed state: %s %d", s, at)
	}

	// Refused by this build: not retried until the agent version changes.
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_FAILED)
	if st, _ := p.Push(ctx, k.DeviceID); st != "up_to_date" {
		t.Errorf("failed retried on the same build: %s", st)
	}
	pool.Exec(ctx, `UPDATE agents SET agent_version = '1.1' WHERE id = $1`, k.AgentUUID)
	if st, _ := p.Push(ctx, k.DeviceID); st != "dispatched" {
		t.Errorf("failed not retried after upgrade: %s", st)
	}
	// NOT_APPLICABLE (already has it) counts as applied.
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_NOT_APPLICABLE)
	if s, _ := status(); s != "applied" {
		t.Errorf("after NOT_APPLICABLE: %s", s)
	}

	// Offline: state pending, nothing sent, pushed on connect.
	agents.up[k.DeviceID] = false
	d4, _ := ParseRequest([]byte(`{}`))
	store.Publish(ctx, d4, "", clientID, "policy-test")
	before := agents.count(k.DeviceID)
	if st, _ := p.Push(ctx, k.DeviceID); st != "offline" || agents.count(k.DeviceID) != before {
		t.Errorf("offline push: %s", st)
	}

	var audits int
	pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'agent_policy.publish' AND actor_api_client_id = $1`, clientID).Scan(&audits)
	if audits != 4 {
		t.Errorf("publish audits: %d", audits)
	}
}
