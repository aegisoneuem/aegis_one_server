// Package commands is the agent_commands audit trail: every command pushed to an
// agent gets a row BEFORE it is sent, and the agent's CommandResult/InstallStatus
// replies move that row through queued -> dispatched -> acknowledged ->
// succeeded/failed/rejected_signature. The row's UUID is used as the wire
// Command.CommandId, which is how replies find their row again.
package commands

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	agentcontrolv1 "aegis-one/gen/agentcontrol/v1"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultTTL fills agent_commands.expires_at (NOT NULL). The agentcontrol/v1
// agent does not enforce expiry - there is no expiry field on the wire - so this
// is bookkeeping for the server side only.
const DefaultTTL = 24 * time.Hour

var ErrNoAgent = errors.New("no live (non-revoked) agent for this device_id")

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ResolveSigningKey returns the signing_keys.id for the public half of key,
// registering it (status 'pending') if it isn't there yet - agent_commands
// requires every row to reference the key that signed it.
func (s *Store) ResolveSigningKey(ctx context.Context, key ed25519.PrivateKey, keyFile string) (string, error) {
	pubB64 := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO signing_keys (key_purpose, public_key, vault_key_ref, status)
		VALUES ('command_signing', $1, $2, 'pending')
		ON CONFLICT (public_key) DO UPDATE SET public_key = EXCLUDED.public_key
		RETURNING id`, pubB64, "local-file:"+keyFile).Scan(&id)
	return id, err
}

// AgentForDevice resolves the live agent bound to an agent-reported device_id
// (see internal/identity).
func (s *Store) AgentForDevice(ctx context.Context, deviceID string) (string, error) {
	var agentID string
	err := s.pool.QueryRow(ctx, `
		SELECT a.id FROM agents a
		JOIN devices d ON d.id = a.device_id
		WHERE d.agent_reported_id = $1 AND a.revoked_at IS NULL`, deviceID).Scan(&agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoAgent
	}
	return agentID, err
}

type Issue struct {
	AgentUUID      string
	DeviceID       string // for the audit_log entry only
	Type           string
	Payload        map[string]any // human-readable form of the wire payload, stored as JSONB
	Signature      []byte
	SigningKeyID   string
	IdempotencyKey string

	IssuedByAPIClientID string // the authenticated caller (api_clients.id)
	IssuedByLabel       string // api_clients.name, for audit_log.actor_label
}

// Existing describes the row already holding an idempotency key.
type Existing struct {
	ID     string
	Status string
}

// Create inserts the agent_commands row (status 'queued') and an audit_log entry
// in one transaction. If the idempotency key was already used, nothing is
// inserted and the earlier row is returned instead - a retried push must never
// execute twice.
func (s *Store) Create(ctx context.Context, in Issue) (id string, existing *Existing, err error) {
	payloadJSON, err := json.Marshal(in.Payload)
	if err != nil {
		return "", nil, fmt.Errorf("marshal payload: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	err = tx.QueryRow(ctx, `
		INSERT INTO agent_commands
			(agent_id, command_type, payload, idempotency_key, signature_ed25519, signing_key_id, expires_at, issued_by_api_client_id)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8)
		ON CONFLICT (idempotency_key) DO NOTHING
		RETURNING id`,
		in.AgentUUID, in.Type, string(payloadJSON), in.IdempotencyKey,
		base64.StdEncoding.EncodeToString(in.Signature), in.SigningKeyID, time.Now().Add(DefaultTTL), in.IssuedByAPIClientID,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		var ex Existing
		if err := tx.QueryRow(ctx,
			`SELECT id, status FROM agent_commands WHERE idempotency_key = $1`, in.IdempotencyKey,
		).Scan(&ex.ID, &ex.Status); err != nil {
			return "", nil, fmt.Errorf("look up existing command: %w", err)
		}
		return "", &ex, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("insert agent_commands: %w", err)
	}

	details, _ := json.Marshal(map[string]any{
		"command_id":   id,
		"command_type": in.Type,
		"device_id":    in.DeviceID,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', $1, $2, 'agent.command.issue', 'agent', $3, $4::jsonb)`,
		in.IssuedByAPIClientID, in.IssuedByLabel, in.AgentUUID, string(details),
	); err != nil {
		return "", nil, fmt.Errorf("insert audit_log: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", nil, err
	}
	return id, nil, nil
}

// MarkDispatched records that the command was handed to the live connection.
// Guarded on 'queued' so a fast agent reply that already moved it to
// 'acknowledged' isn't overwritten.
func (s *Store) MarkDispatched(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE agent_commands SET status = 'dispatched', dispatched_at = now() WHERE id = $1 AND status = 'queued'`, id)
	return err
}

// MarkFailed records a command that never reached the agent (e.g. not connected).
// There is no offline delivery queue in this contract, so it is terminal.
func (s *Store) MarkFailed(ctx context.Context, id, reason string) error {
	result, _ := json.Marshal(map[string]any{"error": reason})
	_, err := s.pool.Exec(ctx, `
		UPDATE agent_commands SET status = 'failed', completed_at = now(), result = $2::jsonb
		WHERE id = $1 AND status = 'queued'`, id, string(result))
	return err
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// nonTerminal is the WHERE guard for agent replies: once a command is
// succeeded/failed/rejected/expired, late or duplicate replies don't move it.
const nonTerminal = `status IN ('queued', 'dispatched', 'acknowledged')`

// ApplyCommandResult moves the command to its final state from a CommandResult.
// Scoped to agentUUID so one agent can't update another agent's commands.
// Returns false (no error) when the command_id isn't one of ours.
func (s *Store) ApplyCommandResult(ctx context.Context, agentUUID string, cr *agentcontrolv1.CommandResult) (bool, error) {
	if !uuidRe.MatchString(cr.GetCommandId()) {
		return false, nil
	}
	status := "failed"
	switch cr.GetStatus() {
	case "success":
		status = "succeeded"
	case "rejected": // the agent only sends this when signature verification fails
		status = "rejected_signature"
	}
	result, _ := json.Marshal(map[string]any{"status": cr.GetStatus(), "message": cr.GetMessage()})
	tag, err := s.pool.Exec(ctx, `
		UPDATE agent_commands SET status = $3, completed_at = now(), result = $4::jsonb
		WHERE id = $1::uuid AND agent_id = $2 AND `+nonTerminal,
		cr.GetCommandId(), agentUUID, status, string(result))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ApplyInstallStatus maps install_patch phases onto agent_commands.status:
// QUEUED..RUNNING -> 'acknowledged' (the CHECK constraint has no in-progress
// state), SUCCESS -> 'succeeded', FAILED -> 'failed'. The latest phase detail is
// kept in result either way.
func (s *Store) ApplyInstallStatus(ctx context.Context, agentUUID string, st *agentcontrolv1.InstallStatus) (bool, error) {
	if !uuidRe.MatchString(st.GetCommandId()) {
		return false, nil
	}
	status, terminal := "acknowledged", false
	switch st.GetPhase() {
	case agentcontrolv1.InstallPhase_INSTALL_PHASE_SUCCESS:
		status, terminal = "succeeded", true
	case agentcontrolv1.InstallPhase_INSTALL_PHASE_FAILED:
		status, terminal = "failed", true
	}
	result, _ := json.Marshal(map[string]any{
		"kb":              st.GetKb(),
		"phase":           st.GetPhase().String(),
		"exit_code":       st.GetExitCode(),
		"reboot_required": st.GetRebootRequired(),
		"reason":          st.GetReason(),
		"detail":          st.GetDetail(),
	})
	tag, err := s.pool.Exec(ctx, `
		UPDATE agent_commands
		SET status = $3, result = $4::jsonb,
		    completed_at = CASE WHEN $5 THEN now() ELSE completed_at END
		WHERE id = $1::uuid AND agent_id = $2 AND `+nonTerminal,
		st.GetCommandId(), agentUUID, status, string(result), terminal)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
