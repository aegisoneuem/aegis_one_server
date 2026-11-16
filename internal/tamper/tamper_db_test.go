package tamper

// Integration test against a throwaway database with all migrations applied:
//
//	AEGIS_TEST_DATABASE_URL=postgres://aegis_server:...@localhost:5433/postgres go test ./internal/tamper/
//
// Skipped when the variable is unset. tamper.* settings are fleet-wide: the
// test changes them and puts the defaults back at the end.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/commands"
	"aegis-one/internal/identity"
	"aegis-one/internal/secretbox"
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
func (f *fakeAgents) Connected(dev string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up[dev]
}
func (f *fakeAgents) ConnectedDevices() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
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

type wireSet struct {
	Mode     string `json:"mode"`
	Passcode string `json:"passcode"`
	IssuedAt int64  `json:"issued_at"`
	MaxTries int    `json:"max_tries"`
}

func TestTamperLifecycleDB(t *testing.T) {
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
	if err := pool.QueryRow(ctx, `INSERT INTO api_clients (name, role_id) SELECT 'tamper-test-'||$1, id FROM roles WHERE name = 'admin' RETURNING id`,
		rnd()).Scan(&clientID); err != nil {
		t.Fatal(err)
	}
	k := &identity.Known{DeviceID: "dev-" + rnd()}
	pool.QueryRow(ctx, `INSERT INTO devices (hostname, os_family, agent_reported_id, last_seen_at) VALUES ('PC-TMP', 'windows', $1, now()) RETURNING id`, k.DeviceID).Scan(&k.DeviceUUID)
	pool.QueryRow(ctx, `INSERT INTO agents (device_id, agent_version, install_method) VALUES ($1, '1.0', 'unknown') RETURNING id`, k.DeviceUUID).Scan(&k.AgentUUID)
	// The agent lists capabilities, but not set_unprotect_secret / stop_agent (7dc4487).
	pool.Exec(ctx, `UPDATE agents SET agent_capabilities = ARRAY['install_patch'] WHERE id = $1`, k.AgentUUID)

	rawKey := make([]byte, 32)
	rand.Read(rawKey)
	box, _ := secretbox.New(rawKey)
	agents := &fakeAgents{sent: map[string][]*aegisonev1.Command{}, up: map[string]bool{k.DeviceID: true}}
	svc := New(ctx, pool, box, &commands.Sender{Store: cmdStore, Disp: agents, Key: key, KeyID: keyID}, agents, log)
	svc.workers = 2

	defaults := Settings{RotationDays: 30, MaxTries: 3, SilentAlertMinutes: 60}
	defer svc.SaveSettings(ctx, defaults, clientID, "tamper-test") //nolint:errcheck
	if err := svc.SaveSettings(ctx, defaults, clientID, "tamper-test"); err != nil {
		t.Fatal(err)
	}

	state := func() (status string, mode *string) {
		pool.QueryRow(ctx, `SELECT status, pending_mode FROM agent_unprotect_secrets WHERE agent_id = $1`, k.AgentUUID).Scan(&status, &mode)
		return
	}
	answer := func(cmd *aegisonev1.Command, phase aegisonev1.ActionPhase) {
		st := &aegisonev1.ActionStatus{ActionId: cmd.GetCommandId(), ActionType: SetCommand, Phase: phase, Reason: "test"}
		cmdStore.ApplyActionStatus(ctx, k.AgentUUID, st)
		svc.ActionStatus(ctx, k, st)
	}
	decode := func(cmd *aegisonev1.Command) wireSet {
		t.Helper()
		var w wireSet
		if cmd == nil || cmd.GetType() != SetCommand {
			t.Fatalf("not a set_unprotect_secret: %+v", cmd)
		}
		if !signing.VerifyCommand(pub, cmd.GetType(), cmd.GetCommandId(), cmd.GetPayload(), cmd.GetSignature()) {
			t.Fatal("signature does not verify")
		}
		json.Unmarshal(cmd.GetPayload(), &w)
		return w
	}
	ageInFlight := func() {
		pool.Exec(ctx, `UPDATE agent_unprotect_secrets SET pending_since = now() - interval '1 hour' WHERE agent_id = $1`, k.AgentUUID)
	}

	// 1. Off by default: a connect sends nothing and creates no row.
	svc.Connected(ctx, k)
	if agents.count(k.DeviceID) != 0 {
		t.Fatal("sent while disabled")
	}
	if _, err := svc.Push(ctx, k.DeviceID, true, "x"); err != ErrDisabled {
		t.Errorf("rotate while disabled: %v", err)
	}

	// 2. Enable: the connected agent gets its own passcode, signed; nothing secret is stored in clear.
	on := defaults
	on.Enabled = true
	if err := svc.SaveSettings(ctx, on, clientID, "tamper-test"); err != nil {
		t.Fatal(err)
	}
	if c := svc.Broadcast(ctx); c["dispatched"] < 1 {
		t.Fatalf("broadcast: %v", c)
	}
	w1 := decode(agents.last(k.DeviceID))
	if w1.Mode != "static" || len(w1.Passcode) != passcodeLen || w1.MaxTries != 3 || w1.IssuedAt == 0 {
		t.Fatalf("wire: %+v", w1)
	}
	if s, m := state(); s != "pending" || m == nil || *m != "set" {
		t.Fatalf("after send: %s %v", s, m)
	}
	var stored []byte
	var auditPayload string
	pool.QueryRow(ctx, `SELECT pending_secret FROM agent_unprotect_secrets WHERE agent_id = $1`, k.AgentUUID).Scan(&stored)
	pool.QueryRow(ctx, `SELECT payload::text FROM agent_commands WHERE id = $1`, agents.last(k.DeviceID).GetCommandId()).Scan(&auditPayload)
	if bytes.Contains(stored, []byte(w1.Passcode)) || strings.Contains(auditPayload, w1.Passcode) {
		t.Fatal("passcode stored in clear")
	}

	// 3. Reconnect right away: in flight, not re-sent. Later: the SAME passcode again.
	if st, _ := svc.Push(ctx, k.DeviceID, false, "x"); st != "in_flight" {
		t.Errorf("immediate re-push: %s", st)
	}
	ageInFlight()
	svc.Connected(ctx, k)
	if w := decode(agents.last(k.DeviceID)); w.Passcode != w1.Passcode || w.IssuedAt != w1.IssuedAt || agents.count(k.DeviceID) != 2 {
		t.Fatalf("resend: %+v vs %+v", w, w1)
	}
	oldCmd := agents.sent[k.DeviceID][0]

	// 4. Confirmed: applied; reveal shows it and is audited.
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS)
	if s, m := state(); s != "applied" || m != nil {
		t.Fatalf("after SUCCESS: %s %v", s, m)
	}
	rv, err := svc.Reveal(ctx, k.DeviceID, clientID, "tamper-test")
	if err != nil || rv.Passcode != w1.Passcode || rv.PendingPasscode != "" || rv.IssuedAt == nil || *rv.IssuedAt != w1.IssuedAt {
		t.Fatalf("reveal: %+v %v", rv, err)
	}
	if st, _ := svc.Push(ctx, k.DeviceID, false, "x"); st != "up_to_date" {
		t.Errorf("applied re-push: %s", st)
	}

	// 5. Manual rotation: new passcode, newer issued_at; until confirmed the old one is shown, the new as pending.
	if st, err := svc.Push(ctx, k.DeviceID, true, "manual rotation"); err != nil || st != "dispatched" {
		t.Fatalf("rotate: %s %v", st, err)
	}
	w2 := decode(agents.last(k.DeviceID))
	if w2.Passcode == w1.Passcode || w2.IssuedAt <= w1.IssuedAt {
		t.Fatalf("rotation: %+v after %+v", w2, w1)
	}
	rv, _ = svc.Reveal(ctx, k.DeviceID, clientID, "tamper-test")
	if rv.Passcode != w1.Passcode || rv.PendingPasscode != w2.Passcode {
		t.Errorf("reveal during rotation: %+v", rv)
	}
	// A late answer to an old command changes nothing.
	answer(oldCmd, aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS)
	if s, _ := state(); s != "pending" {
		t.Errorf("stale answer applied: %s", s)
	}
	// NOT_APPLICABLE ("not newer") = the agent already has the pending one.
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_NOT_APPLICABLE)
	rv, _ = svc.Reveal(ctx, k.DeviceID, clientID, "tamper-test")
	if s, _ := state(); s != "applied" || rv.Passcode != w2.Passcode {
		t.Errorf("after NOT_APPLICABLE: %s %+v", s, rv)
	}

	// 6. Scheduled rotation: the scheduler sends a new passcode to a connected agent that is due.
	pool.Exec(ctx, `UPDATE agent_unprotect_secrets SET rotate_after = now() - interval '1 minute' WHERE agent_id = $1`, k.AgentUUID)
	before := agents.count(k.DeviceID)
	svc.RunOnce(ctx)
	if agents.count(k.DeviceID) != before+1 {
		t.Fatalf("scheduler did not rotate")
	}
	w3 := decode(agents.last(k.DeviceID))
	if w3.IssuedAt <= w2.IssuedAt {
		t.Errorf("issued_at %d after %d", w3.IssuedAt, w2.IssuedAt)
	}
	// 7. Refused: failed, not retried on the same build, retried after an upgrade.
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_FAILED)
	if s, _ := state(); s != "failed" {
		t.Errorf("after FAILED: %s", s)
	}
	rv, _ = svc.Reveal(ctx, k.DeviceID, clientID, "tamper-test")
	if rv.Passcode != w2.Passcode {
		t.Errorf("refused rotation must keep showing the applied passcode: %+v", rv)
	}
	if st, _ := svc.Push(ctx, k.DeviceID, false, "x"); st != "up_to_date" {
		t.Errorf("failed retried on same build: %s", st)
	}
	pool.Exec(ctx, `UPDATE agents SET agent_version = '1.1' WHERE id = $1`, k.AgentUUID)
	if st, _ := svc.Push(ctx, k.DeviceID, false, "x"); st != "dispatched" {
		t.Errorf("failed not retried after upgrade: %s", st)
	}
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS)

	// 8. Tamper events: alerts; a deleted passcode store gets a new passcode at once.
	svc.AuditEvent(ctx, k, &aegisonev1.AuditEvent{EventType: "binary_tampered", Reason: "exe replaced; restored from backup"})
	svc.AuditEvent(ctx, k, &aegisonev1.AuditEvent{EventType: "binary_tampered"})
	var sev string
	var occ int
	pool.QueryRow(ctx, `SELECT severity, occurrence_count FROM alerts WHERE dedup_key = $1 AND status = 'open'`, alertKey("binary_tampered", k.DeviceUUID)).Scan(&sev, &occ)
	if sev != "high" || occ != 2 {
		t.Errorf("binary alert: %s x%d", sev, occ)
	}
	before = agents.count(k.DeviceID)
	svc.AuditEvent(ctx, k, &aegisonev1.AuditEvent{EventType: "unprotect_secret_tampered"})
	if agents.count(k.DeviceID) != before+1 {
		t.Fatal("no new passcode after store deletion")
	}
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS)
	svc.AuditEvent(ctx, k, &aegisonev1.AuditEvent{EventType: "unprotect_secret_set"}) // informational: no alert
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE device_id = $1 AND alert_type = $2`, k.DeviceUUID, AlertType).Scan(&n)
	if n != 2 {
		t.Errorf("tamper alerts: %d", n)
	}

	// 9. Silent after tamper: escalated to critical once.
	pool.Exec(ctx, `UPDATE devices SET last_seen_at = now() - interval '3 hours' WHERE id = $1`, k.DeviceUUID)
	if c, err := svc.EscalateSilent(ctx); err != nil || c < 2 {
		t.Errorf("escalate: %d %v", c, err)
	}
	if c, _ := svc.EscalateSilent(ctx); c != 0 {
		t.Errorf("escalated twice: %d", c)
	}
	pool.QueryRow(ctx, `SELECT severity FROM alerts WHERE dedup_key = $1 AND status = 'open'`, alertKey("binary_tampered", k.DeviceUUID)).Scan(&sev)
	if sev != "critical" {
		t.Errorf("after silence: %s", sev)
	}

	// 10. Tokens: device-bound, expiring, signed with the command key; stop_agent carries one.
	tok, err := svc.IssueToken(ctx, k.DeviceID, 30*time.Minute, clientID, "tamper-test")
	if err != nil {
		t.Fatal(err)
	}
	checkToken := func(s string, maxTTL time.Duration) {
		t.Helper()
		parts := strings.Split(s, ".")
		p, _ := base64.RawURLEncoding.DecodeString(parts[0])
		sig, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if len(parts) != 2 || !ed25519.Verify(pub, p, sig) {
			t.Fatalf("token signature: %q", s)
		}
		var c struct {
			Device string `json:"device"`
			Exp    int64  `json:"exp"`
			Nonce  string `json:"nonce"`
		}
		json.Unmarshal(p, &c)
		left := time.Until(time.Unix(c.Exp, 0))
		if c.Device != k.DeviceID || c.Nonce == "" || left <= 0 || left > maxTTL {
			t.Errorf("token claims: %+v", c)
		}
	}
	checkToken(tok.Token, 30*time.Minute)
	if _, err := svc.MintToken("*", time.Minute); err == nil {
		t.Error("wildcard token minted")
	}
	if _, err := svc.MintToken(k.DeviceID, 48*time.Hour); err == nil {
		t.Error("token beyond max ttl minted")
	}
	sent, err := svc.Stop(ctx, k.DeviceID, clientID, "tamper-test")
	if err != nil || sent.Status != "dispatched" {
		t.Fatalf("stop: %+v %v", sent, err)
	}
	stop := agents.last(k.DeviceID)
	if stop.GetType() != StopCommand || !signing.VerifyCommand(pub, stop.GetType(), stop.GetCommandId(), stop.GetPayload(), stop.GetSignature()) {
		t.Fatalf("stop command: %+v", stop)
	}
	checkToken(string(stop.GetPayload()), StopTokenTTL)
	pool.QueryRow(ctx, `SELECT payload::text FROM agent_commands WHERE id = $1`, stop.GetCommandId()).Scan(&auditPayload)
	if strings.Contains(auditPayload, string(stop.GetPayload())) {
		t.Error("stop token stored in agent_commands")
	}
	if _, err := svc.Stop(ctx, "no-such-"+rnd(), clientID, "tamper-test"); err != ErrUnknownDevice {
		t.Errorf("stop unknown: %v", err)
	}

	// 11. Detail view: state, open alerts, agent events.
	pool.Exec(ctx, `INSERT INTO agent_audit_events (device_id, agent_id, ts, event_type, decision) VALUES ($1, $2, now(), 'agent_stop_refused', 'refused')`,
		k.DeviceUUID, k.AgentUUID)
	d, err := svc.Device(ctx, k.DeviceID)
	if err != nil || d.Status != "applied" || len(d.Alerts) != 2 || len(d.Events) != 1 {
		t.Errorf("device view: %+v %v", d, err)
	}

	// 12. Disable: a clear goes out; offline first, then on connect; confirmed -> cleared, nothing to reveal.
	agents.up[k.DeviceID] = false
	if err := svc.SaveSettings(ctx, defaults, clientID, "tamper-test"); err != nil {
		t.Fatal(err)
	}
	if st, _ := svc.Push(ctx, k.DeviceID, false, "settings changed"); st != "offline" {
		t.Errorf("offline clear: %s", st)
	}
	agents.up[k.DeviceID] = true
	ageInFlight()
	svc.Connected(ctx, k)
	clr := decode(agents.last(k.DeviceID))
	if clr.Mode != "clear" || clr.Passcode != "" {
		t.Fatalf("clear wire: %+v", clr)
	}
	answer(agents.last(k.DeviceID), aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS)
	rv, _ = svc.Reveal(ctx, k.DeviceID, clientID, "tamper-test")
	if s, _ := state(); s != "cleared" || rv.Passcode != "" {
		t.Errorf("after clear: %s %+v", s, rv)
	}
	if st, _ := svc.Push(ctx, k.DeviceID, false, "x"); st != "disabled" {
		t.Errorf("cleared re-push: %s", st)
	}

	var reveals, tokens, settings int
	pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action = 'agent_tamper.reveal'), count(*) FILTER (WHERE action = 'agent_tamper.token'),
		count(*) FILTER (WHERE action = 'agent_tamper.settings') FROM audit_log WHERE actor_api_client_id = $1`, clientID).Scan(&reveals, &tokens, &settings)
	if reveals != 5 || tokens != 1 || settings != 3 {
		t.Errorf("audit: reveals %d tokens %d settings %d", reveals, tokens, settings)
	}
}

func TestPasscodeAndSettings(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := NewPasscode()
		if err != nil || len(p) != passcodeLen || strings.Trim(p, passcodeAlphabet) != "" {
			t.Fatalf("passcode %q %v", p, err)
		}
		if strings.ContainsAny(p, "0O1IL") || seen[p] {
			t.Fatalf("ambiguous or repeated passcode %q", p)
		}
		seen[p] = true
	}
	ok := Settings{RotationDays: 0, MaxTries: 3, SilentAlertMinutes: 60}
	if ok.Validate() != nil {
		t.Error("valid settings rejected")
	}
	for _, bad := range []Settings{{RotationDays: -1, MaxTries: 3, SilentAlertMinutes: 60}, {MaxTries: 0, SilentAlertMinutes: 60},
		{MaxTries: 3, SilentAlertMinutes: 1}, {MaxTries: 11, SilentAlertMinutes: 60}} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	w, audit := setPayload("set", "ABCDEFGHJK", 5, 3)
	if !strings.Contains(string(w), "ABCDEFGHJK") || audit["passcode"] != nil {
		t.Errorf("set payload %s / %v", w, audit)
	}
	w, _ = setPayload("clear", "", 6, 3)
	if string(w) != `{"issued_at":6,"mode":"clear"}` {
		t.Errorf("clear payload %s", w)
	}
}
