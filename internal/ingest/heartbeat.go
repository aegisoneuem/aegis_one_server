// Package ingest persists agent-reported data (heartbeats, patch scan results)
// into Postgres, keyed by the identity internal/identity has already resolved.
// Callers only invoke these once a connection has a known identity - there is no
// device/agent to attach the data to otherwise.
package ingest

import (
	"context"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Heartbeat records one agent_heartbeats row, bumps agents.last_heartbeat_at /
// devices.last_seen_at, and keeps the device's hostname and the agent's
// version, schema version, capabilities and device type current. No
// CPU/RAM/disk telemetry is in this contract's Heartbeat, so those columns
// stay NULL.
func (s *Store) Heartbeat(ctx context.Context, known *identity.Known, hb *aegisonev1.Heartbeat) error {
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
	caps := make([]string, 0, len(hb.GetAgentCapabilities()))
	for _, c := range hb.GetAgentCapabilities() {
		if c = clipN(c, 100); c != "" && len(caps) < 100 {
			caps = append(caps, c)
		}
	}
	// Older agents send no schema_version / capabilities / device_type; keep
	// what is stored rather than blanking it.
	if _, err := tx.Exec(ctx, `
		UPDATE agents SET last_heartbeat_at = now(),
		    agent_version      = coalesce($2, agent_version),
		    schema_version     = coalesce($3, schema_version),
		    agent_capabilities = CASE WHEN cardinality($4::text[]) > 0 THEN $4 ELSE agent_capabilities END,
		    device_type        = coalesce($5, device_type)
		WHERE id = $1`,
		known.AgentUUID, nullableN(hb.GetAgentVersion(), 100), nullableN(hb.GetSchemaVersion(), 100), caps,
		nullableN(hb.GetDeviceType(), 100)); err != nil {
		return err
	}
	// Hostname is a mutable attribute (renames happen), never an identity key.
	if _, err := tx.Exec(ctx, `UPDATE devices SET last_seen_at = now(), hostname = coalesce($2, hostname) WHERE id = $1`,
		known.DeviceUUID, nullableN(hb.GetHostname(), 255)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
