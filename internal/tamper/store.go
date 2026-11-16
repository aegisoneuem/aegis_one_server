package tamper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Settings are the tamper.* rows of system_settings.
type Settings struct {
	Enabled            bool `json:"enabled"`
	RotationDays       int  `json:"rotation_days"`        // 0 = never
	MaxTries           int  `json:"max_tries"`            // GUI uninstall prompt attempts
	SilentAlertMinutes int  `json:"silent_alert_minutes"` // escalate an open tamper alert after this silence
}

// Validate checks the ranges the API accepts.
func (s Settings) Validate() error {
	switch {
	case s.RotationDays < 0 || s.RotationDays > 3650:
		return errors.New("rotation_days must be 0..3650 (0 = never)")
	case s.MaxTries < 1 || s.MaxTries > 10:
		return errors.New("max_tries must be 1..10")
	case s.SilentAlertMinutes < 5 || s.SilentAlertMinutes > 10080:
		return errors.New("silent_alert_minutes must be 5..10080")
	}
	return nil
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// LoadSettings reads the settings; missing rows take the 0028 defaults.
func LoadSettings(ctx context.Context, q querier) (Settings, error) {
	st := Settings{RotationDays: 30, MaxTries: 3, SilentAlertMinutes: 60}
	rows, err := q.Query(ctx, `SELECT key, value #>> '{}' FROM system_settings WHERE key LIKE 'tamper.%'`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return st, err
		}
		n, nerr := strconv.Atoi(v)
		switch k {
		case "tamper.enabled":
			st.Enabled = v == "true"
		case "tamper.rotation_days":
			if nerr == nil {
				st.RotationDays = n
			}
		case "tamper.max_tries":
			if nerr == nil {
				st.MaxTries = n
			}
		case "tamper.silent_alert_minutes":
			if nerr == nil {
				st.SilentAlertMinutes = n
			}
		}
	}
	return st, rows.Err()
}

// SaveSettings stores st, re-dates scheduled rotations for the new
// rotation_days, and writes an audit_log entry, in one transaction.
func (s *Service) SaveSettings(ctx context.Context, st Settings, clientID, clientName string) error {
	if err := st.Validate(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	for k, v := range map[string]string{
		"tamper.enabled":              strconv.FormatBool(st.Enabled),
		"tamper.rotation_days":        strconv.Itoa(st.RotationDays),
		"tamper.max_tries":            strconv.Itoa(st.MaxTries),
		"tamper.silent_alert_minutes": strconv.Itoa(st.SilentAlertMinutes),
	} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO system_settings (key, value) VALUES ($1, $2::jsonb)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, k, v); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_unprotect_secrets SET rotate_after = CASE WHEN $1 > 0 THEN applied_at + make_interval(days => $1) END
		WHERE status = 'applied'`, st.RotationDays); err != nil {
		return err
	}
	details, _ := json.Marshal(st)
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, details)
		VALUES ('api_client', $1, $2, 'agent_tamper.settings', 'system_settings', $3::jsonb)`,
		clientID, clientName, string(details)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// FleetCounts counts live agents by passcode state; not_provisioned = no row.
func (s *Service) FleetCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT coalesce(s.status, 'not_provisioned'), count(*)
		FROM agents a LEFT JOIN agent_unprotect_secrets s ON s.agent_id = a.id
		WHERE a.revoked_at IS NULL GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{"applied": 0, "pending": 0, "failed": 0, "cleared": 0, "not_provisioned": 0}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// DeviceState is one agent's passcode state (never the passcode).
type DeviceState struct {
	DeviceID        string     `json:"device_id"`
	Hostname        string     `json:"hostname,omitempty"`
	Status          string     `json:"status"` // applied | pending | failed | cleared | not_provisioned
	AppliedIssuedAt *int64     `json:"applied_issued_at,omitempty"`
	AppliedAt       *time.Time `json:"applied_at,omitempty"`
	PendingMode     *string    `json:"pending_mode,omitempty"`
	PendingSince    *time.Time `json:"pending_since,omitempty"`
	RotateAfter     *time.Time `json:"rotate_after,omitempty"`
	Reason          *string    `json:"reason,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

const selectState = `SELECT d.agent_reported_id, coalesce(d.hostname, ''), coalesce(s.status, 'not_provisioned'),
	s.applied_issued_at, s.applied_at, s.pending_mode, s.pending_since, s.rotate_after, s.reason, s.updated_at
	FROM agents a JOIN devices d ON d.id = a.device_id
	LEFT JOIN agent_unprotect_secrets s ON s.agent_id = a.id
	WHERE a.revoked_at IS NULL AND d.agent_reported_id IS NOT NULL`

func scanState(row pgx.Row) (DeviceState, error) {
	var d DeviceState
	err := row.Scan(&d.DeviceID, &d.Hostname, &d.Status, &d.AppliedIssuedAt, &d.AppliedAt, &d.PendingMode,
		&d.PendingSince, &d.RotateAfter, &d.Reason, &d.UpdatedAt)
	return d, err
}

// Devices lists agent states, optionally one status, newest change first.
func (s *Service) Devices(ctx context.Context, status string, limit int) ([]DeviceState, error) {
	rows, err := s.pool.Query(ctx, selectState+`
		AND ($1 = '' OR coalesce(s.status, 'not_provisioned') = $1)
		ORDER BY s.updated_at DESC NULLS LAST, d.agent_reported_id LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceState{}
	for rows.Next() {
		d, err := scanState(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AgentEvent is one tamper-related agent audit event.
type AgentEvent struct {
	TS        time.Time `json:"ts"`
	EventType string    `json:"event_type"`
	Decision  *string   `json:"decision,omitempty"`
	Reason    *string   `json:"reason,omitempty"`
	CommandID *string   `json:"command_id,omitempty"`
	Actor     *string   `json:"actor,omitempty"`
}

// AlertView is one tamper alert of the device.
type AlertView struct {
	ID              string          `json:"id"`
	Severity        string          `json:"severity"`
	Status          string          `json:"status"`
	Title           string          `json:"title"`
	OccurrenceCount int             `json:"occurrence_count"`
	FirstSeenAt     time.Time       `json:"first_seen_at"`
	LastSeenAt      time.Time       `json:"last_seen_at"`
	Details         json.RawMessage `json:"details"`
}

// DeviceDetail is the per-device tamper view.
type DeviceDetail struct {
	DeviceState
	Alerts []AlertView  `json:"alerts"`
	Events []AgentEvent `json:"events"`
}

// Device returns one device's state, its open tamper alerts and the last 20
// tamper-related agent audit events.
func (s *Service) Device(ctx context.Context, deviceID string) (*DeviceDetail, error) {
	st, err := scanState(s.pool.QueryRow(ctx, selectState+` AND d.agent_reported_id = $1`, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownDevice
	}
	if err != nil {
		return nil, err
	}
	out := &DeviceDetail{DeviceState: st, Alerts: []AlertView{}, Events: []AgentEvent{}}
	rows, err := s.pool.Query(ctx, `
		SELECT al.id::text, al.severity, al.status, al.title, al.occurrence_count, al.first_seen_at, al.last_seen_at, al.details
		FROM alerts al JOIN devices d ON d.id = al.device_id
		WHERE d.agent_reported_id = $1 AND al.alert_type = $2 AND al.status <> 'resolved'
		ORDER BY al.last_seen_at DESC LIMIT 50`, deviceID, AlertType)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a AlertView
		if err := rows.Scan(&a.ID, &a.Severity, &a.Status, &a.Title, &a.OccurrenceCount, &a.FirstSeenAt, &a.LastSeenAt, &a.Details); err != nil {
			rows.Close()
			return nil, err
		}
		out.Alerts = append(out.Alerts, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.pool.Query(ctx, `
		SELECT e.ts, e.event_type, e.decision, e.reason, e.command_id, e.actor
		FROM agent_audit_events e JOIN devices d ON d.id = e.device_id
		WHERE d.agent_reported_id = $1 AND e.event_type = ANY($2)
		ORDER BY e.ts DESC LIMIT 20`, deviceID, AuditEventTypes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e AgentEvent
		if err := rows.Scan(&e.TS, &e.EventType, &e.Decision, &e.Reason, &e.CommandID, &e.Actor); err != nil {
			return nil, err
		}
		out.Events = append(out.Events, e)
	}
	return out, rows.Err()
}

// Revealed is what an operator with agent.tamper.reveal is shown. Passcode is
// the one the agent confirmed. While a newer one is unconfirmed (agent offline,
// or its answer lost) it is shown as PendingPasscode: if Passcode is refused,
// the agent has the pending one.
type Revealed struct {
	DeviceID        string     `json:"device_id"`
	Status          string     `json:"status"`
	Passcode        string     `json:"passcode,omitempty"`
	IssuedAt        *int64     `json:"issued_at,omitempty"`
	AppliedAt       *time.Time `json:"applied_at,omitempty"`
	PendingPasscode string     `json:"pending_passcode,omitempty"`
	PendingSince    *time.Time `json:"pending_since,omitempty"`
	Note            string     `json:"note,omitempty"`
}

// Reveal opens the device's passcode(s) and records who looked, in audit_log,
// whether or not there was anything to show.
func (s *Service) Reveal(ctx context.Context, deviceID, clientID, clientName string) (*Revealed, error) {
	a, err := s.agent(ctx, nil, deviceID)
	if err != nil {
		return nil, err
	}
	r, err := scanSecret(s.pool.QueryRow(ctx, selectSecret, a.agentUUID))
	if err != nil {
		return nil, err
	}
	out := &Revealed{DeviceID: deviceID, Status: "not_provisioned"}
	if r.exists {
		out.Status = r.status
		if r.appliedSecret != nil && r.appliedIssuedAt != nil {
			if p, err := s.box.Open(r.appliedSecret, aad(a.agentUUID, *r.appliedIssuedAt)); err == nil {
				out.Passcode, out.IssuedAt, out.AppliedAt = string(p), r.appliedIssuedAt, r.appliedAt
			} else {
				out.Note = "the stored passcode was sealed with another secrets key; rotate it (POST .../rotate)"
			}
		}
		if r.pending("set") && r.pendingIssued != nil {
			if p, err := s.box.Open(r.pendingSecret, aad(a.agentUUID, *r.pendingIssued)); err == nil {
				out.PendingPasscode, out.PendingSince = string(p), r.pendingSince
			}
		}
	}
	details, _ := json.Marshal(map[string]any{"device_id": deviceID, "status": out.Status,
		"applied_issued_at": out.IssuedAt, "pending_shown": out.PendingPasscode != ""})
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', $1, $2, 'agent_tamper.reveal', 'agent', $3, $4::jsonb)`,
		clientID, clientName, a.agentUUID, string(details)); err != nil {
		return nil, fmt.Errorf("audit reveal: %w", err) // no audit row, no passcode
	}
	return out, nil
}

// IssueToken mints a break-glass token for a known device and audits it.
func (s *Service) IssueToken(ctx context.Context, deviceID string, ttl time.Duration, clientID, clientName string) (Token, error) {
	a, err := s.agent(ctx, nil, deviceID)
	if err != nil {
		return Token{}, err
	}
	tok, err := s.MintToken(deviceID, ttl)
	if err != nil {
		return Token{}, err
	}
	details, _ := json.Marshal(map[string]any{"device_id": deviceID, "expires_at": tok.ExpiresAt, "nonce": tok.nonce})
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', $1, $2, 'agent_tamper.token', 'agent', $3, $4::jsonb)`,
		clientID, clientName, a.agentUUID, string(details)); err != nil {
		return Token{}, fmt.Errorf("audit token: %w", err)
	}
	return tok, nil
}
