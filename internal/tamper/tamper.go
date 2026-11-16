// Package tamper is the server side of agent tamper protection (agent 7dc4487,
// Phase A, docs/server-integration-tamper-protection.md in the agent repo).
//
// Once an agent holds an unprotect passcode it refuses sc stop / disable /
// delete and a normal uninstall; it stops or uninstalls only for that passcode
// or for an Ed25519 token signed with the command key. This package:
//
//   - gives each agent its own random passcode (signed set_unprotect_secret),
//     stored only sealed (internal/secretbox), re-sent on connect until the
//     agent confirms it, rotated every tamper.rotation_days;
//   - clears the passcodes again when tamper.enabled is turned off;
//   - reveals a device's passcode to holders of agent.tamper.reveal (audited);
//   - mints short-lived per-device tokens: for a console "stop agent"
//     (stop_agent command) and as a break-glass credential for an operator;
//   - turns the agent's tamper audit events into alerts, gives an agent that
//     lost its passcode store a new one, and raises an open tamper alert to
//     critical when the device then goes silent (the "wiped everything" case
//     the agent cannot defend alone).
package tamper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"sync"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/commands"
	"aegis-one/internal/identity"
	"aegis-one/internal/secretbox"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// SetCommand provisions, rotates or clears the agent's passcode.
	SetCommand = "set_unprotect_secret"
	// StopCommand stops a self-protected agent; payload = passcode or token.
	StopCommand = "stop_agent"

	passcodeLen = 10
	// No 0/O, 1/I/L: the passcode is read aloud and typed by hand.
	passcodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

	// StopTokenTTL bounds the token inside a console stop_agent command.
	StopTokenTTL = 10 * time.Minute
	// DefaultTokenTTL / MaxTokenTTL bound a break-glass token.
	DefaultTokenTTL = time.Hour
	MaxTokenTTL     = 24 * time.Hour

	// inFlight: a set/clear sent this recently is not sent again (connect,
	// tamper event and scheduler can race for one device).
	inFlight = 30 * time.Second
	// stalePending: the scheduler re-sends an unanswered set/clear after this.
	stalePending = 15 * time.Minute
	// tick is the scheduler period (rotations, stale pendings, silent devices).
	tick = 5 * time.Minute
)

// AlertType is alerts.alert_type for agent tamper events.
const AlertType = "agent_tampered"

// alertEvents maps agent audit events to alert severity.
var alertEvents = map[string]string{
	"unprotect_secret_tampered": "high",   // passcode store deleted; agent stays protected
	"binary_tampered":           "high",   // exe deleted/replaced, restored from backup
	"service_tampered":          "high",   // service DACL / start type reset by the watchdog
	"agent_stop_refused":        "medium", // wrong passcode/token (stop, CLI or uninstall)
}

// AuditEventTypes are the agent audit events shown in a device's tamper view.
var AuditEventTypes = []string{
	"unprotect_secret_set", "unprotect_secret_cleared", "unprotect_secret_tampered",
	"agent_stop_authorized", "agent_stop_refused", "service_tampered", "binary_tampered",
}

// Live lists the agents connected right now.
type Live interface {
	ConnectedDevices() []string
}

// Service is the tamper-protection pusher, scheduler and credential source.
type Service struct {
	pool    *pgxpool.Pool
	box     *secretbox.Box
	sender  *commands.Sender
	live    Live
	log     *slog.Logger
	base    context.Context // server lifetime
	now     func() time.Time
	workers int
}

func New(base context.Context, pool *pgxpool.Pool, box *secretbox.Box, sender *commands.Sender, live Live, log *slog.Logger) *Service {
	return &Service{pool: pool, box: box, sender: sender, live: live, log: log, base: base, now: time.Now, workers: 16}
}

// ErrUnknownDevice: no live (non-revoked) agent for the device_id.
var ErrUnknownDevice = errors.New("unknown device_id (never connected, or its agent is revoked)")

// ErrDisabled: tamper protection is off, so there is nothing to rotate.
var ErrDisabled = errors.New("tamper protection is disabled (tamper.enabled = false)")

type agentRef struct {
	agentUUID, agentVersion, hostname string
}

func (s *Service) agent(ctx context.Context, q pgx.Tx, deviceID string) (agentRef, error) {
	var a agentRef
	row := `SELECT a.id::text, coalesce(a.agent_version, ''), coalesce(d.hostname, '')
		FROM agents a JOIN devices d ON d.id = a.device_id
		WHERE d.agent_reported_id = $1 AND a.revoked_at IS NULL`
	var err error
	if q != nil {
		err = q.QueryRow(ctx, row, deviceID).Scan(&a.agentUUID, &a.agentVersion, &a.hostname)
	} else {
		err = s.pool.QueryRow(ctx, row, deviceID).Scan(&a.agentUUID, &a.agentVersion, &a.hostname)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrUnknownDevice
	}
	return a, err
}

// secretRow is agent_unprotect_secrets.
type secretRow struct {
	exists          bool
	keyID           *string
	appliedSecret   []byte
	appliedIssuedAt *int64
	appliedAt       *time.Time
	pendingMode     *string
	pendingSecret   []byte
	pendingIssued   *int64
	pendingSince    *time.Time
	status          string
	reason          *string
	agentVersion    *string
	rotateAfter     *time.Time
}

const selectSecret = `SELECT key_id, applied_secret, applied_issued_at, applied_at, pending_mode, pending_secret,
	pending_issued_at, pending_since, status, reason, agent_version, rotate_after
	FROM agent_unprotect_secrets WHERE agent_id = $1`

func scanSecret(row pgx.Row) (secretRow, error) {
	var r secretRow
	err := row.Scan(&r.keyID, &r.appliedSecret, &r.appliedIssuedAt, &r.appliedAt, &r.pendingMode, &r.pendingSecret,
		&r.pendingIssued, &r.pendingSince, &r.status, &r.reason, &r.agentVersion, &r.rotateAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return secretRow{}, nil
	}
	r.exists = err == nil
	return r, err
}

func (r secretRow) pending(mode string) bool { return r.pendingMode != nil && *r.pendingMode == mode }

// aad binds a sealed passcode to its agent and issued_at.
func aad(agentUUID string, issuedAt int64) []byte {
	return []byte("aegis-unprotect-v1|" + agentUUID + "|" + strconv.FormatInt(issuedAt, 10))
}

// nextIssuedAt is strictly newer than anything this agent was ever sent: the
// agent refuses a set/clear whose issued_at is not newer (anti-rollback).
func (s *Service) nextIssuedAt(r secretRow) int64 {
	n := s.now().Unix()
	for _, v := range []*int64{r.appliedIssuedAt, r.pendingIssued} {
		if v != nil && *v >= n {
			n = *v + 1
		}
	}
	return n
}

// NewPasscode returns a random passcode from passcodeAlphabet (~49 bits).
func NewPasscode() (string, error) {
	b := make([]byte, passcodeLen)
	max := big.NewInt(int64(len(passcodeAlphabet)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = passcodeAlphabet[n.Int64()]
	}
	return string(b), nil
}

// Push brings one device's passcode in line with the settings: provision,
// re-send an unconfirmed one, rotate when due (or when rotate is set), or
// clear when protection is off. Returns what happened: disabled | up_to_date |
// in_flight | unknown_device | or the commands.Sent status (dispatched,
// offline, failed, ...).
func (s *Service) Push(ctx context.Context, deviceID string, rotate bool, why string) (string, error) {
	st, err := LoadSettings(ctx, s.pool)
	if err != nil {
		return "", err
	}
	if rotate && !st.Enabled {
		return "disabled", ErrDisabled
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	a, err := s.agent(ctx, tx, deviceID)
	if errors.Is(err, ErrUnknownDevice) {
		return "unknown_device", nil
	}
	if err != nil {
		return "", err
	}
	if st.Enabled {
		if _, err := tx.Exec(ctx, `INSERT INTO agent_unprotect_secrets (agent_id, status) VALUES ($1, 'cleared') ON CONFLICT DO NOTHING`, a.agentUUID); err != nil {
			return "", err
		}
	}
	r, err := scanSecret(tx.QueryRow(ctx, selectSecret+` FOR UPDATE`, a.agentUUID))
	if err != nil {
		return "", err
	}
	if !r.exists {
		return "disabled", nil
	}
	now := s.now()
	recent := r.pendingMode != nil && r.pendingSince != nil && now.Sub(*r.pendingSince) < inFlight
	sameBuild := r.agentVersion != nil && *r.agentVersion == a.agentVersion

	// Decide: "set" (new passcode), "resend" (the pending one again), "clear".
	action := ""
	if st.Enabled {
		switch {
		case rotate:
			action = "set"
		case r.pending("set"):
			if recent {
				return "in_flight", nil
			}
			action = "resend"
		case r.status == "failed" && sameBuild:
			return "up_to_date", nil // refused by this build; retried after an upgrade
		case r.status == "applied" && r.appliedSecret != nil:
			if r.rotateAfter == nil || now.Before(*r.rotateAfter) {
				return "up_to_date", nil
			}
			action, why = "set", "scheduled rotation"
		default:
			action = "set"
		}
	} else {
		switch {
		case r.pending("clear"):
			if recent {
				return "in_flight", nil
			}
			action = "resend"
		case r.status == "cleared" && r.pendingMode == nil:
			return "disabled", nil
		case r.status == "failed" && sameBuild:
			return "up_to_date", nil
		default:
			action = "clear"
		}
	}

	var passcode string
	issuedAt := int64(0)
	mode := action
	switch action {
	case "resend":
		mode, issuedAt = *r.pendingMode, *r.pendingIssued
		if mode == "set" {
			plain, err := s.box.Open(r.pendingSecret, aad(a.agentUUID, issuedAt))
			if err != nil {
				// Sealed under another master key: start over with a new passcode.
				s.log.Warn("pending unprotect passcode unreadable; issuing a new one", "device_id", deviceID, "error", err.Error())
				mode, issuedAt = "set", 0
			} else {
				passcode = string(plain)
			}
		}
	}
	if issuedAt == 0 {
		issuedAt = s.nextIssuedAt(r)
		var sealed []byte
		if mode == "set" {
			if passcode, err = NewPasscode(); err != nil {
				return "", err
			}
			if sealed, err = s.box.Seal([]byte(passcode), aad(a.agentUUID, issuedAt)); err != nil {
				return "", err
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE agent_unprotect_secrets SET key_id = $2, pending_mode = $3, pending_secret = $4, pending_issued_at = $5,
			    pending_since = now(), pending_command_id = NULL, status = 'pending', reason = NULLIF($6, ''), updated_at = now()
			WHERE agent_id = $1`, a.agentUUID, s.box.KeyID(), mode, sealed, issuedAt, why); err != nil {
			return "", err
		}
	} else if _, err := tx.Exec(ctx, `UPDATE agent_unprotect_secrets SET pending_since = now(), updated_at = now() WHERE agent_id = $1`, a.agentUUID); err != nil {
		return "", err
	}
	// State is committed before sending: the agent may answer before Send returns.
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	wire, audit := setPayload(mode, passcode, issuedAt, st.MaxTries)
	audit["reason"] = why
	sent, err := s.sender.Send(ctx, commands.SendRequest{
		DeviceID: deviceID, Type: SetCommand, Wire: wire, Audit: audit,
		ClientName: "tamper protection", Actor: "tamper_protection",
		// The agent (7dc4487) does not list set_unprotect_secret in its capabilities.
		SkipCapabilityCheck: true,
	})
	if err != nil {
		return "", err
	}
	if sent.CommandID != "" {
		if _, err := s.pool.Exec(ctx, `UPDATE agent_unprotect_secrets SET pending_command_id = $2 WHERE agent_id = $1 AND pending_issued_at = $3`,
			a.agentUUID, sent.CommandID, issuedAt); err != nil {
			return sent.Status, err
		}
	}
	if sent.Status == "dispatched" {
		s.log.Info("unprotect passcode sent", "device_id", deviceID, "mode", mode, "issued_at", issuedAt, "reason", why)
	}
	return sent.Status, nil
}

// setPayload builds the signed wire JSON and the agent_commands audit copy,
// which never holds the passcode.
func setPayload(mode, passcode string, issuedAt int64, maxTries int) ([]byte, map[string]any) {
	audit := map[string]any{"mode": mode, "issued_at": issuedAt}
	if mode == "clear" {
		w, _ := json.Marshal(map[string]any{"mode": "clear", "issued_at": issuedAt})
		return w, audit
	}
	audit["max_tries"] = maxTries
	w, _ := json.Marshal(map[string]any{"mode": "static", "passcode": passcode, "issued_at": issuedAt, "max_tries": maxTries})
	return w, audit
}

// Connected is called for every agent connection with a resolved identity.
func (s *Service) Connected(ctx context.Context, known *identity.Known) {
	if status, err := s.Push(ctx, known.DeviceID, false, "agent connected"); err != nil {
		s.log.Error("unprotect passcode push on connect failed", "device_id", known.DeviceID, "error", err.Error())
	} else if status == "dispatched" {
		s.log.Info("unprotect passcode pushed on connect", "device_id", known.DeviceID)
	}
}

// ActionStatus records the agent's answer to a set_unprotect_secret command.
// SUCCESS applies the pending set/clear. NOT_APPLICABLE ("not newer than the
// active one") also counts as applied: every issued_at comes from this server
// and the pending one is the newest, so the agent already has it (an earlier
// answer was lost). FAILED is a refusal. The pending entry is matched by the
// command's issued_at, so an answer to an older command changes nothing.
func (s *Service) ActionStatus(ctx context.Context, known *identity.Known, st *aegisonev1.ActionStatus) {
	if st.GetActionType() != SetCommand || !commands.IsCommandID(st.GetActionId()) {
		return
	}
	reason := clip(st.GetReason(), 1024)
	var q string
	switch st.GetPhase() {
	case aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, aegisonev1.ActionPhase_ACTION_PHASE_NOT_APPLICABLE:
		q = `UPDATE agent_unprotect_secrets s SET
		    applied_secret    = CASE WHEN s.pending_mode = 'set' THEN s.pending_secret END,
		    applied_issued_at = s.pending_issued_at,
		    applied_at        = CASE WHEN s.pending_mode = 'set' THEN now() END,
		    status            = CASE WHEN s.pending_mode = 'set' THEN 'applied' ELSE 'cleared' END,
		    rotate_after      = CASE WHEN s.pending_mode = 'set' AND setting_int('tamper.rotation_days', 30) > 0
		                             THEN now() + make_interval(days => setting_int('tamper.rotation_days', 30)) END,`
	case aegisonev1.ActionPhase_ACTION_PHASE_FAILED:
		q = `UPDATE agent_unprotect_secrets s SET status = 'failed',`
	default:
		return
	}
	q += `
		    reason = NULLIF($3, ''), agent_version = (SELECT agent_version FROM agents WHERE id = $1),
		    pending_mode = NULL, pending_secret = NULL, pending_issued_at = NULL, pending_command_id = NULL,
		    pending_since = NULL, updated_at = now()
		FROM agent_commands c
		WHERE s.agent_id = $1 AND c.id = $2::uuid AND c.agent_id = $1 AND c.command_type = '` + SetCommand + `'
		  AND s.pending_issued_at = (c.payload->>'issued_at')::bigint
		RETURNING s.status`
	var status string
	err := s.pool.QueryRow(ctx, q, known.AgentUUID, st.GetActionId(), reason).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return // answer to a set/clear that is no longer the pending one
	}
	if err != nil {
		s.log.Error("record unprotect passcode result failed", "device_id", known.DeviceID, "error", err.Error())
		return
	}
	if status == "failed" {
		s.log.Warn("agent refused unprotect passcode", "device_id", known.DeviceID, "reason", reason)
	} else {
		s.log.Info("unprotect passcode result", "device_id", known.DeviceID, "status", status)
	}
}

// AuditEvent turns the agent's tamper events into alerts. An agent whose
// passcode store was deleted (it stays protected, fail-closed) gets a new
// passcode right away. Alerts stay open for an admin, like policy tamper.
func (s *Service) AuditEvent(ctx context.Context, known *identity.Known, ev *aegisonev1.AuditEvent) {
	severity, ok := alertEvents[ev.GetEventType()]
	if !ok {
		return
	}
	details, _ := json.Marshal(map[string]any{"device_id": known.DeviceID, "event_type": ev.GetEventType(),
		"decision": ev.GetDecision(), "reason": clip(ev.GetReason(), 1024), "command_id": ev.GetCommandId(), "actor": ev.GetActor()})
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO alerts (alert_type, severity, device_id, title, details, dedup_key)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6)
		ON CONFLICT (dedup_key) WHERE status <> 'resolved' AND dedup_key IS NOT NULL
		DO UPDATE SET occurrence_count = alerts.occurrence_count + 1, last_seen_at = now(),
		    details = alerts.details || EXCLUDED.details`,
		AlertType, severity, known.DeviceUUID, fmt.Sprintf("Agent tamper on %s: %s", known.DeviceID, ev.GetEventType()),
		string(details), alertKey(ev.GetEventType(), known.DeviceUUID)); err != nil {
		s.log.Error("raise tamper alert failed", "device_id", known.DeviceID, "error", err.Error())
	}
	s.log.Warn("agent tamper event", "device_id", known.DeviceID, "event_type", ev.GetEventType(), "reason", ev.GetReason())
	if ev.GetEventType() == "unprotect_secret_tampered" {
		if status, err := s.Push(ctx, known.DeviceID, true, "agent passcode store deleted"); err != nil && !errors.Is(err, ErrDisabled) {
			s.log.Error("unprotect passcode re-provision failed", "device_id", known.DeviceID, "error", err.Error())
		} else {
			s.log.Info("unprotect passcode re-provisioned after tamper", "device_id", known.DeviceID, "status", status)
		}
	}
}

func alertKey(eventType, deviceUUID string) string {
	return AlertType + ":" + eventType + ":" + deviceUUID
}

// Broadcast runs Push for every connected agent, a few at a time (after the
// settings change). Offline agents are handled when they connect.
func (s *Service) Broadcast(ctx context.Context) map[string]int {
	devs := s.live.ConnectedDevices()
	return s.pushAll(ctx, devs, "settings changed")
}

func (s *Service) pushAll(ctx context.Context, devs []string, why string) map[string]int {
	ch := make(chan string)
	var mu sync.Mutex
	counts := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dev := range ch {
				status, err := s.Push(ctx, dev, false, why)
				if err != nil {
					s.log.Error("unprotect passcode push failed", "device_id", dev, "error", err.Error())
					status = "error"
				}
				mu.Lock()
				counts[status]++
				mu.Unlock()
			}
		}()
	}
	for _, d := range devs {
		select {
		case ch <- d:
		case <-ctx.Done():
		}
	}
	close(ch)
	wg.Wait()
	return counts
}

// BroadcastAsync runs Broadcast on the server's lifetime context.
func (s *Service) BroadcastAsync() {
	go func() {
		counts := s.Broadcast(s.base)
		s.log.Info("tamper protection broadcast done", "result", counts)
	}()
}

// Run is the scheduler: every few minutes it rotates due passcodes and
// re-sends unanswered ones on connected agents, and escalates tamper alerts
// of devices that went silent. Blocks until ctx is done.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RunOnce(ctx)
		}
	}
}

// RunOnce is one scheduler pass.
func (s *Service) RunOnce(ctx context.Context) {
	if devs, err := s.dueDevices(ctx); err != nil {
		s.log.Error("tamper scheduler: list due devices failed", "error", err.Error())
	} else if len(devs) > 0 {
		s.log.Info("tamper scheduler pushes", "result", s.pushAll(ctx, devs, "scheduled"))
	}
	if n, err := s.EscalateSilent(ctx); err != nil {
		s.log.Error("tamper scheduler: escalate silent devices failed", "error", err.Error())
	} else if n > 0 {
		s.log.Warn("tamper alerts escalated: device silent after tamper", "count", n)
	}
}

// dueDevices: connected agents whose passcode is due for rotation, or whose
// set/clear has gone unanswered.
func (s *Service) dueDevices(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d.agent_reported_id FROM agent_unprotect_secrets s
		JOIN agents a ON a.id = s.agent_id AND a.revoked_at IS NULL
		JOIN devices d ON d.id = a.device_id
		WHERE d.agent_reported_id IS NOT NULL
		  AND ((s.status = 'applied' AND s.rotate_after < now())
		    OR (s.pending_mode IS NOT NULL AND s.pending_since < now() - make_interval(secs => $1)))
		LIMIT 10000`, stalePending.Seconds())
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := ids[:0]
	for _, id := range ids {
		if s.sender.Disp.Connected(id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// EscalateSilent raises open tamper alerts to critical for devices silent
// longer than tamper.silent_alert_minutes: the agent may have been removed
// beyond what it can self-heal, so the device needs a re-deploy. Once per alert.
func (s *Service) EscalateSilent(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE alerts a SET severity = 'critical',
		    details = a.details || jsonb_build_object('silent_escalated_at', now(), 'last_seen_at', coalesce(d.last_seen_at, d.first_seen_at))
		FROM devices d
		WHERE a.alert_type = $1 AND a.status <> 'resolved' AND a.device_id = d.id
		  AND NOT a.details ? 'silent_escalated_at'
		  AND coalesce(d.last_seen_at, d.first_seen_at) < now() - make_interval(mins => setting_int('tamper.silent_alert_minutes', 60))`,
		AlertType)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// Token is a device-bound unprotect token the agent accepts in place of the
// passcode: base64url(payload) "." base64url(ed25519 signature over payload),
// signed with the command key. Never "*" (any device) and never without expiry.
type Token struct {
	Token     string    `json:"token"`
	DeviceID  string    `json:"device_id"`
	ExpiresAt time.Time `json:"expires_at"`
	nonce     string
}

// MintToken signs a token for deviceID valid for ttl (capped at MaxTokenTTL).
func (s *Service) MintToken(deviceID string, ttl time.Duration) (Token, error) {
	if s.sender == nil || len(s.sender.Key) != ed25519.PrivateKeySize {
		return Token{}, errors.New("command signing key not loaded")
	}
	if deviceID == "" || deviceID == "*" {
		return Token{}, errors.New("a token is bound to one device_id")
	}
	if ttl <= 0 || ttl > MaxTokenTTL {
		return Token{}, fmt.Errorf("ttl must be between 1 minute and %s", MaxTokenTTL)
	}
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return Token{}, err
	}
	exp := s.now().Add(ttl).Truncate(time.Second)
	nonce := hex.EncodeToString(nb)
	payload, err := json.Marshal(struct {
		Device string `json:"device"`
		Exp    int64  `json:"exp"`
		Nonce  string `json:"nonce"`
	}{deviceID, exp.Unix(), nonce})
	if err != nil {
		return Token{}, err
	}
	sig := ed25519.Sign(s.sender.Key, payload)
	return Token{
		Token:    base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig),
		DeviceID: deviceID, ExpiresAt: exp, nonce: nonce,
	}, nil
}

// Stop sends stop_agent with a fresh StopTokenTTL token (never the passcode,
// so nothing secret lands in agent_commands).
func (s *Service) Stop(ctx context.Context, deviceID, clientID, clientName string) (commands.Sent, error) {
	if _, err := s.agent(ctx, nil, deviceID); err != nil {
		return commands.Sent{DeviceID: deviceID}, err
	}
	tok, err := s.MintToken(deviceID, StopTokenTTL)
	if err != nil {
		return commands.Sent{DeviceID: deviceID}, err
	}
	return s.sender.Send(ctx, commands.SendRequest{
		DeviceID: deviceID, Type: StopCommand, Wire: []byte(tok.Token),
		Audit:    map[string]any{"credential": "token", "token_expires_at": tok.ExpiresAt, "token_nonce": tok.nonce},
		ClientID: clientID, ClientName: clientName, Actor: "api_client:" + clientName,
		SkipCapabilityCheck: true, // not in the agent's capability list either
	})
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
