package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/commands"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CommandType is the agent command that carries the policy.
const CommandType = "set_policy"

// Agent audit event types that mean its stored policy is gone or was changed.
// The agent then runs in fail-closed safe mode (run_command, open_shell,
// file_operation and remote_control refused) until the policy is sent again.
var tamperEvents = map[string]string{
	"policy_tampered":  "high",
	"policy_safe_mode": "high",
	"policy_lockdown":  "critical", // repeated tampering
}

// Live lists the agents connected right now.
type Live interface {
	ConnectedDevices() []string
}

// Pusher sends the current policy to agents that don't have it yet.
type Pusher struct {
	pool   *pgxpool.Pool
	store  *Store
	sender *commands.Sender
	live   Live
	log    *slog.Logger
	base   context.Context // server lifetime, for pushes not tied to one request

	workers int
}

func NewPusher(base context.Context, pool *pgxpool.Pool, store *Store, sender *commands.Sender, live Live, log *slog.Logger) *Pusher {
	return &Pusher{pool: pool, store: store, sender: sender, live: live, log: log, base: base, workers: 16}
}

type agentState struct {
	agentUUID, agentVersion string
	issuedAt                *int64
	status, stateVersion    *string
}

// needsPush decides from the stored state whether the agent should get version
// cur: never pushed, an older version, no answer yet (pending), a tamper report,
// or a refusal by an agent build that has since changed.
func needsPush(st agentState, cur int64) bool {
	switch {
	case st.issuedAt == nil || *st.issuedAt != cur:
		return true
	case *st.status == "pending" || *st.status == "tampered":
		return true
	case *st.status == "failed":
		return st.stateVersion == nil || *st.stateVersion != st.agentVersion
	}
	return false
}

// Push sends the current policy to one connected device if it needs it, and
// returns what happened: no_policy | up_to_date | unknown_device | or the
// commands.Sent status (dispatched, offline, failed).
func (p *Pusher) Push(ctx context.Context, deviceID string) (string, error) {
	cur, err := p.store.Current(ctx)
	if err != nil || cur == nil {
		return "no_policy", err
	}
	var st agentState
	err = p.pool.QueryRow(ctx, `
		SELECT a.id::text, coalesce(a.agent_version, ''), s.issued_at, s.status, s.agent_version
		FROM agents a JOIN devices d ON d.id = a.device_id
		LEFT JOIN agent_policy_state s ON s.agent_id = a.id
		WHERE d.agent_reported_id = $1 AND a.revoked_at IS NULL`, deviceID).
		Scan(&st.agentUUID, &st.agentVersion, &st.issuedAt, &st.status, &st.stateVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return "unknown_device", nil
	}
	if err != nil {
		return "", err
	}
	if !needsPush(st, cur.IssuedAt) {
		return "up_to_date", nil
	}
	// State first: the agent may answer before Send returns.
	if _, err := p.pool.Exec(ctx, `
		INSERT INTO agent_policy_state (agent_id, policy_id, issued_at, status, agent_version)
		VALUES ($1, $2, $3, 'pending', NULLIF($4, ''))
		ON CONFLICT (agent_id) DO UPDATE SET policy_id = EXCLUDED.policy_id, issued_at = EXCLUDED.issued_at,
		    status = 'pending', reason = NULL, command_id = NULL, agent_version = EXCLUDED.agent_version, updated_at = now()`,
		st.agentUUID, cur.ID, cur.IssuedAt, st.agentVersion); err != nil {
		return "", err
	}
	sent, err := p.sender.Send(ctx, commands.SendRequest{
		DeviceID: deviceID, Type: CommandType, Wire: cur.Wire,
		Audit:    map[string]any{"policy_id": cur.ID, "issued_at": cur.IssuedAt},
		ClientID: cur.CreatedByID, ClientName: cur.CreatedBy,
		Actor:               "agent_policy:" + strconv.FormatInt(cur.IssuedAt, 10),
		SkipCapabilityCheck: true,
	})
	if err != nil {
		return "", err
	}
	if sent.CommandID != "" {
		if _, err := p.pool.Exec(ctx, `UPDATE agent_policy_state SET command_id = $2 WHERE agent_id = $1 AND issued_at = $3 AND command_id IS NULL`,
			st.agentUUID, sent.CommandID, cur.IssuedAt); err != nil {
			return sent.Status, err
		}
	}
	return sent.Status, nil
}

// Broadcast pushes the current policy to every connected agent that needs it,
// a few at a time. Offline agents get it when they connect.
func (p *Pusher) Broadcast(ctx context.Context) map[string]int {
	devs := p.live.ConnectedDevices()
	ch := make(chan string)
	var mu sync.Mutex
	counts := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dev := range ch {
				status, err := p.Push(ctx, dev)
				if err != nil {
					p.log.Error("policy push failed", "device_id", dev, "error", err.Error())
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
	p.log.Info("policy broadcast done", "connected", len(devs), "result", counts)
	return counts
}

// BroadcastAsync runs Broadcast on the server's lifetime context.
func (p *Pusher) BroadcastAsync() {
	go p.Broadcast(p.base)
}

// Connected is called for every agent connection with a resolved identity.
func (p *Pusher) Connected(ctx context.Context, known *identity.Known) {
	if status, err := p.Push(ctx, known.DeviceID); err != nil {
		p.log.Error("policy push on connect failed", "device_id", known.DeviceID, "error", err.Error())
	} else if status == "dispatched" {
		p.log.Info("policy pushed on connect", "device_id", known.DeviceID)
	}
}

// ActionStatus records the agent's answer to a set_policy command. SUCCESS is
// applied; NOT_APPLICABLE means it already has this version, also applied;
// FAILED is a refusal. The version is taken from the command row, so an answer
// to an older push cannot mark a newer version applied.
func (p *Pusher) ActionStatus(ctx context.Context, known *identity.Known, st *aegisonev1.ActionStatus) {
	if st.GetActionType() != CommandType || !commands.IsCommandID(st.GetActionId()) {
		return
	}
	var status string
	switch st.GetPhase() {
	case aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, aegisonev1.ActionPhase_ACTION_PHASE_NOT_APPLICABLE:
		status = "applied"
	case aegisonev1.ActionPhase_ACTION_PHASE_FAILED:
		status = "failed"
	default:
		return
	}
	reason := st.GetReason()
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	tag, err := p.pool.Exec(ctx, `
		UPDATE agent_policy_state s SET status = $3, reason = NULLIF($4, ''), updated_at = now()
		FROM agent_commands c
		WHERE s.agent_id = $1 AND c.id = $2::uuid AND c.agent_id = $1 AND c.command_type = 'set_policy'
		  AND s.issued_at = (c.payload->>'issued_at')::bigint`,
		known.AgentUUID, st.GetActionId(), status, reason)
	if err != nil {
		p.log.Error("record policy result failed", "device_id", known.DeviceID, "error", err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		return // answer to a version that is no longer the one tracked
	}
	p.log.Info("policy result", "device_id", known.DeviceID, "status", status, "reason", reason)
	// A tamper alert stays open after recovery: tampering is a security event an
	// admin must look at even though the policy is back. Only note the recovery.
	if status == "applied" {
		if _, err := p.pool.Exec(ctx, `UPDATE alerts SET details = details || jsonb_build_object('policy_reapplied_at', now())
			WHERE dedup_key = $1 AND status <> 'resolved'`, alertKey(known.DeviceUUID)); err != nil {
			p.log.Error("update policy alert failed", "device_id", known.DeviceID, "error", err.Error())
		}
	}
}

// AuditEvent reacts to the agent reporting its stored policy deleted, edited or
// rolled back: open (or bump) an alert and send the current policy again. The
// alert is left for an admin to acknowledge / resolve.
func (p *Pusher) AuditEvent(ctx context.Context, known *identity.Known, ev *aegisonev1.AuditEvent) {
	severity, ok := tamperEvents[ev.GetEventType()]
	if !ok {
		return
	}
	reason := ev.GetEventType()
	if r := ev.GetReason(); r != "" {
		reason += ": " + r
	}
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	if _, err := p.pool.Exec(ctx, `UPDATE agent_policy_state SET status = 'tampered', reason = $2, updated_at = now() WHERE agent_id = $1`,
		known.AgentUUID, reason); err != nil {
		p.log.Error("record policy tamper failed", "device_id", known.DeviceID, "error", err.Error())
	}
	details, _ := json.Marshal(map[string]any{"device_id": known.DeviceID, "event_type": ev.GetEventType(),
		"decision": ev.GetDecision(), "reason": ev.GetReason()})
	if _, err := p.pool.Exec(ctx, `
		INSERT INTO alerts (alert_type, severity, device_id, title, details, dedup_key)
		VALUES ('agent_policy_tampered', $1, $2, $3, $4::jsonb, $5)
		ON CONFLICT (dedup_key) WHERE status <> 'resolved' AND dedup_key IS NOT NULL
		DO UPDATE SET occurrence_count = alerts.occurrence_count + 1, last_seen_at = now(), details = EXCLUDED.details,
		    severity = CASE WHEN EXCLUDED.severity = 'critical' THEN 'critical' ELSE alerts.severity END`,
		severity, known.DeviceUUID, fmt.Sprintf("Agent policy tampered on %s (%s)", known.DeviceID, ev.GetEventType()),
		string(details), alertKey(known.DeviceUUID)); err != nil {
		p.log.Error("raise policy alert failed", "device_id", known.DeviceID, "error", err.Error())
	}
	p.log.Warn("agent reported policy tampering; re-sending policy", "device_id", known.DeviceID, "event_type", ev.GetEventType())
	if _, err := p.Push(ctx, known.DeviceID); err != nil {
		p.log.Error("policy re-push failed", "device_id", known.DeviceID, "error", err.Error())
	}
}

func alertKey(deviceUUID string) string { return "agent_policy_tampered:" + deviceUUID }
