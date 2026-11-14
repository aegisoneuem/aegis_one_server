package agentpolicy

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Published is one stored policy version.
type Published struct {
	ID          string          `json:"policy_id"`
	IssuedAt    int64           `json:"issued_at"`
	Document    json.RawMessage `json:"document"`
	Note        string          `json:"note,omitempty"`
	CreatedByID string          `json:"-"`
	CreatedBy   string          `json:"created_by,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	Wire        []byte          `json:"-"`
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Current returns the newest policy, or nil when none was ever published.
func (s *Store) Current(ctx context.Context) (*Published, error) {
	p, err := scanPublished(s.pool.QueryRow(ctx, selectPublished+` ORDER BY issued_at DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// History returns the newest versions first.
func (s *Store) History(ctx context.Context, limit int) ([]Published, error) {
	rows, err := s.pool.Query(ctx, selectPublished+` ORDER BY issued_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Published{}
	for rows.Next() {
		p, err := scanPublished(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

const selectPublished = `SELECT id::text, issued_at, document, coalesce(note, ''), coalesce(created_by_api_client_id::text, ''),
	coalesce(created_by_label, ''), created_at, wire FROM agent_policies`

func scanPublished(row pgx.Row) (*Published, error) {
	var p Published
	var doc []byte
	if err := row.Scan(&p.ID, &p.IssuedAt, &doc, &p.Note, &p.CreatedByID, &p.CreatedBy, &p.CreatedAt, &p.Wire); err != nil {
		return nil, err
	}
	p.Document = doc
	return &p, nil
}

// Publish stores d as the new current version. The server sets version,
// policy_id and issued_at: issued_at is the current unix time, or one more than
// the newest stored version when that is not earlier (two publishes in one
// second, or a clock that went back), so every version is strictly newer and
// agents accept it.
func (s *Store) Publish(ctx context.Context, d *Document, note, clientID, clientName string) (*Published, error) {
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('aegis.agent_policy.publish'))`); err != nil {
		return nil, err
	}
	var last int64
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(issued_at), 0) FROM agent_policies`).Scan(&last); err != nil {
		return nil, err
	}
	doc := *d
	doc.Version, doc.PolicyID, doc.IssuedAt = 1, id, max(time.Now().Unix(), last+1)
	wire, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var notePtr *string
	if note != "" {
		notePtr = &note
	}
	p, err := scanPublished(tx.QueryRow(ctx, `
		INSERT INTO agent_policies (id, issued_at, document, wire, note, created_by_api_client_id, created_by_label)
		VALUES ($1, $2, $3::jsonb, $4, $5, NULLIF($6, '')::uuid, NULLIF($7, ''))
		RETURNING id::text, issued_at, document, coalesce(note, ''), coalesce(created_by_api_client_id::text, ''),
		    coalesce(created_by_label, ''), created_at, wire`,
		id, doc.IssuedAt, string(wire), wire, notePtr, clientID, clientName))
	if err != nil {
		return nil, fmt.Errorf("insert agent_policies: %w", err)
	}
	details, _ := json.Marshal(map[string]any{"policy_id": id, "issued_at": doc.IssuedAt, "summary": doc.Summary(), "note": note})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', NULLIF($1, '')::uuid, $2, 'agent_policy.publish', 'agent_policy', $3, $4::jsonb)`,
		clientID, clientName, id, string(details)); err != nil {
		return nil, fmt.Errorf("insert audit_log: %w", err)
	}
	return p, tx.Commit(ctx)
}

// FleetCounts says how many live agents are at each state for the current
// version; "not_pushed" are agents with no state for it yet.
func (s *Store) FleetCounts(ctx context.Context, issuedAt int64) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT CASE WHEN st.issued_at IS DISTINCT FROM $1 THEN 'not_pushed' ELSE st.status END, count(*)
		FROM agents a LEFT JOIN agent_policy_state st ON st.agent_id = a.id
		WHERE a.revoked_at IS NULL GROUP BY 1`, issuedAt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{"applied": 0, "pending": 0, "failed": 0, "tampered": 0, "not_pushed": 0}
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

// DeviceState is one agent's policy state.
type DeviceState struct {
	DeviceID     string    `json:"device_id"`
	Hostname     string    `json:"hostname"`
	PolicyID     string    `json:"policy_id"`
	IssuedAt     int64     `json:"issued_at"`
	Current      bool      `json:"current"`
	Status       string    `json:"status"`
	Reason       string    `json:"reason,omitempty"`
	CommandID    string    `json:"command_id,omitempty"`
	AgentVersion string    `json:"agent_version,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Devices lists agent policy states, optionally for one status.
func (s *Store) Devices(ctx context.Context, status string, limit int) ([]DeviceState, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT coalesce(d.agent_reported_id, ''), d.hostname, st.policy_id::text, st.issued_at,
		    st.issued_at = (SELECT max(issued_at) FROM agent_policies), st.status, coalesce(st.reason, ''),
		    coalesce(st.command_id::text, ''), coalesce(st.agent_version, ''), st.updated_at
		FROM agent_policy_state st
		JOIN agents a ON a.id = st.agent_id AND a.revoked_at IS NULL
		JOIN devices d ON d.id = a.device_id
		WHERE $1 = '' OR st.status = $1
		ORDER BY st.updated_at DESC LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceState{}
	for rows.Next() {
		var r DeviceState
		if err := rows.Scan(&r.DeviceID, &r.Hostname, &r.PolicyID, &r.IssuedAt, &r.Current, &r.Status, &r.Reason,
			&r.CommandID, &r.AgentVersion, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
