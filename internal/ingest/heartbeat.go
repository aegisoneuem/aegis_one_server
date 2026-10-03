// Package ingest persists agent-reported data (heartbeats, patch scan results)
// into Postgres, keyed by the identity internal/identity has already resolved.
// Callers only invoke these once a connection has a known identity - there is no
// device/agent to attach the data to otherwise.
package ingest

import (
	"context"

	agentcontrolv1 "aegis-one/gen/agentcontrol/v1"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Heartbeat records one agent_heartbeats row and bumps agents.last_heartbeat_at /
// devices.last_seen_at. No CPU/RAM/disk telemetry is in this contract's Heartbeat,
// so those columns stay NULL.
func (s *Store) Heartbeat(ctx context.Context, known *identity.Known, hb *agentcontrolv1.Heartbeat) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_heartbeats (agent_id, device_id, agent_version, connection_state)
		VALUES ($1, $2, $3, 'connected')`,
		known.AgentUUID, known.DeviceUUID, hb.GetAgentVersion(),
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE agents SET last_heartbeat_at = now() WHERE id = $1`, known.AgentUUID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET last_seen_at = now() WHERE id = $1`, known.DeviceUUID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
