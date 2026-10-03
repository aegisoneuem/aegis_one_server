// Package identity implements trust-on-first-use (TOFU) agent identity for the
// agentcontrol/v1 contract, which has no EnrollmentService: the first time an
// mTLS client certificate fingerprint is seen alongside an agent-reported
// device_id, it is bound permanently (devices/agents/agent_certificates rows
// created). From then on, that device_id may only connect with that same
// fingerprint - a different fingerprint claiming an already-bound device_id is
// refused, which is what keeps one agent from impersonating another's device_id.
//
// This is weaker than real enrollment (first contact is unauthenticated beyond
// "signed by our CA") but matches CLAUDE.md's rule that identity must come from
// the certificate, not a message field, for every connection AFTER the first.
package identity

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Known struct {
	DeviceUUID string
	DeviceID   string // agent-reported free-text id (devices.agent_reported_id)
	AgentUUID  string
	Revoked    bool
}

type Resolver struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Resolver {
	return &Resolver{pool: pool}
}

// Enabled reports whether identity tracking is active. It is a no-op (every
// connection trusted exactly as before) when no database is configured, matching
// how /readyz and ingestion behave when AEGIS_DATABASE_URL is unset.
func (r *Resolver) Enabled() bool {
	return r.pool != nil
}

// Lookup returns the identity already bound to fingerprint, or nil if this
// fingerprint has never been seen before. Only call when Enabled().
func (r *Resolver) Lookup(ctx context.Context, fingerprint string) (*Known, error) {
	var k Known
	var deviceID *string
	err := r.pool.QueryRow(ctx, `
		SELECT d.id, d.agent_reported_id, a.id, (ac.revoked_at IS NOT NULL OR a.revoked_at IS NOT NULL)
		FROM agent_certificates ac
		JOIN agents a ON a.id = ac.agent_id
		JOIN devices d ON d.id = a.device_id
		WHERE ac.fingerprint_sha256 = $1`, fingerprint,
	).Scan(&k.DeviceUUID, &deviceID, &k.AgentUUID, &k.Revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if deviceID != nil {
		k.DeviceID = *deviceID
	}
	return &k, nil
}

// Bootstrap binds fingerprint to deviceID, creating devices/agents/
// agent_certificates rows as needed. It refuses if deviceID already has a live
// (non-revoked) agent bound to a DIFFERENT fingerprint. Only call when Enabled(),
// and only for a fingerprint Lookup has not already resolved.
func (r *Resolver) Bootstrap(ctx context.Context, fingerprint string, cert *x509.Certificate, deviceID, hostname, osFamily, agentVersion string) (*Known, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("device_id is required")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	var conflictFingerprint string
	err = tx.QueryRow(ctx, `
		SELECT ac.fingerprint_sha256
		FROM devices d
		JOIN agents a ON a.device_id = d.id AND a.revoked_at IS NULL
		JOIN agent_certificates ac ON ac.agent_id = a.id AND ac.revoked_at IS NULL
		WHERE d.agent_reported_id = $1`, deviceID).Scan(&conflictFingerprint)
	if err == nil {
		return nil, fmt.Errorf("device_id %q already has a live agent bound to a different certificate - refusing to auto-bind a new one (revoke the old agent first if this is a legitimate replacement)", deviceID)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("check existing binding: %w", err)
	}

	var deviceUUID string
	err = tx.QueryRow(ctx, `SELECT id FROM devices WHERE agent_reported_id = $1`, deviceID).Scan(&deviceUUID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			INSERT INTO devices (hostname, os_family, agent_reported_id, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, now(), now())
			RETURNING id`, firstNonEmpty(hostname, deviceID), normalizeOSFamily(osFamily), deviceID,
		).Scan(&deviceUUID)
	}
	if err != nil {
		return nil, fmt.Errorf("find-or-create device: %w", err)
	}

	var agentUUID string
	err = tx.QueryRow(ctx, `
		INSERT INTO agents (device_id, agent_version, install_method)
		VALUES ($1, $2, 'unknown')
		RETURNING id`, deviceUUID, firstNonEmpty(agentVersion, "unknown")).Scan(&agentUUID)
	if err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_certificates (agent_id, serial_number, fingerprint_sha256, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5)`,
		agentUUID, cert.SerialNumber.String(), fingerprint, cert.NotBefore, cert.NotAfter,
	); err != nil {
		return nil, fmt.Errorf("record certificate: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return &Known{DeviceUUID: deviceUUID, DeviceID: deviceID, AgentUUID: agentUUID}, nil
}

func firstNonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func normalizeOSFamily(os string) string {
	switch strings.ToLower(strings.TrimSpace(os)) {
	case "windows", "linux", "macos":
		return strings.ToLower(os)
	default:
		return "windows" // this agent is Windows-only today; devices.os_family has no "unknown"
	}
}
