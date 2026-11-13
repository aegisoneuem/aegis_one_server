package devices

// Integration test against a throwaway database with all migrations applied:
//
//	AEGIS_TEST_DATABASE_URL=postgres://aegis_server:...@localhost:5433/postgres go test ./internal/devices/
//
// Skipped when the variable is unset. It creates its own rows with random
// identifiers and never deletes anything.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5/pgxpool"
)

type fakeLive struct {
	connected    map[string]bool
	disconnected []string
}

func (f *fakeLive) Connected(id string) bool { return f.connected[id] }
func (f *fakeLive) Disconnect(id string) bool {
	f.disconnected = append(f.disconnected, id)
	return true
}

func rnd() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type seeded struct {
	uuid, deviceID, agentID, fingerprint string
}

// seedDevice creates a device with one live agent and certificate.
func seedDevice(t *testing.T, pool *pgxpool.Pool, hostname, tpm string, lastSeenDaysAgo int) seeded {
	t.Helper()
	ctx := context.Background()
	s := seeded{deviceID: "dev-" + rnd(), fingerprint: rnd() + rnd() + rnd() + rnd()}
	var tpmArg *string
	if tpm != "" {
		tpmArg = &tpm
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (hostname, os_family, agent_reported_id, tpm_ek, first_seen_at, last_seen_at)
		VALUES ($1, 'windows', $2, $3, now() - interval '90 days', now() - make_interval(days => $4)) RETURNING id`,
		hostname, s.deviceID, tpmArg, lastSeenDaysAgo).Scan(&s.uuid); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agents (device_id, agent_version, install_method) VALUES ($1, '1.0', 'unknown') RETURNING id`,
		s.uuid).Scan(&s.agentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO agent_certificates (agent_id, serial_number, fingerprint_sha256, not_before, not_after)
		VALUES ($1, $2, $3, now(), now() + interval '1 day')`, s.agentID, rnd(), s.fingerprint); err != nil {
		t.Fatal(err)
	}
	return s
}

func candidate(t *testing.T, pool *pgxpool.Pool, n, e seeded) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO device_merge_candidates (new_device_id, existing_device_id, matched_by, matched_value)
		VALUES ($1, $2, 'system_uuid', 'x') RETURNING id`, n.uuid, e.uuid).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDuplicatesDB(t *testing.T) {
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
	live := &fakeLive{connected: map[string]bool{}}
	h := New(pool, live, slog.New(slog.NewTextHandler(io.Discard, nil)))
	const actor, client = "api_client:test", ""

	// The reimaged machine's old record (silent 70 days, so stale_alert) and the
	// record its fresh install created.
	tpmNew := "tpm:" + rnd()
	old := seedDevice(t, pool, "PC-OLD-"+rnd(), "", 70)
	fresh := seedDevice(t, pool, "PC-NEW-"+rnd(), tpmNew, 0)
	other := seedDevice(t, pool, "PC-OTHER-"+rnd(), "", 0)
	candID := candidate(t, pool, fresh, old)
	sideID := candidate(t, pool, fresh, other) // superseded by the merge

	// Listed as pending, with both sides.
	rec := httptest.NewRecorder()
	h.duplicates(rec, httptest.NewRequest("GET", "/internal/devices/duplicates?limit=500", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), candID) || !strings.Contains(rec.Body.String(), old.deviceID) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}

	// Stale alert flag on the old record.
	d, err := scanDevice(pool.QueryRow(ctx, selectSQL+" WHERE d.id = $3", nowMinus(15), nowMinusDays(30), old.uuid))
	if err != nil || !d.StaleAlert || d.State != "stale" {
		t.Fatalf("old record: %+v %v", d, err)
	}

	// The existing record's agent is connected: refused.
	live.connected[old.deviceID] = true
	if _, err := h.merge(ctx, DecideRequest{ID: candID}, actor, client); !isConflict(err) {
		t.Fatalf("merge with a connected existing agent: %v", err)
	}
	live.connected[old.deviceID] = false

	res, err := h.merge(ctx, DecideRequest{ID: candID, Reason: "reimaged"}, actor, client)
	if err != nil {
		t.Fatal(err)
	}
	if res["device_id"] != fresh.deviceID || len(live.disconnected) != 1 || live.disconnected[0] != fresh.deviceID {
		t.Errorf("merge result %v, disconnected %v", res, live.disconnected)
	}

	// The kept record now carries the agent's device_id and TPM; the new one is merged.
	var keptID, keptTPM, keptStatus string
	pool.QueryRow(ctx, `SELECT agent_reported_id, tpm_ek, status FROM devices WHERE id = $1`, old.uuid).Scan(&keptID, &keptTPM, &keptStatus)
	if keptID != fresh.deviceID || keptTPM != tpmNew || keptStatus != "active" {
		t.Errorf("kept record: id=%s tpm=%s status=%s", keptID, keptTPM, keptStatus)
	}
	var mergedInto, mergedStatus string
	var mergedID *string
	pool.QueryRow(ctx, `SELECT merged_into_device_id::text, status, agent_reported_id FROM devices WHERE id = $1`, fresh.uuid).
		Scan(&mergedInto, &mergedStatus, &mergedID)
	if mergedInto != old.uuid || mergedStatus != "decommissioned" || mergedID != nil {
		t.Errorf("merged record: into=%s status=%s id=%v", mergedInto, mergedStatus, mergedID)
	}

	// The agent's certificate now resolves to the kept record; the old agent is revoked.
	k, err := identity.New(pool).Lookup(ctx, fresh.fingerprint)
	if err != nil || k == nil || k.DeviceUUID != old.uuid || k.DeviceID != fresh.deviceID || k.Revoked {
		t.Errorf("identity after merge: %+v %v", k, err)
	}
	if k, _ := identity.New(pool).Lookup(ctx, old.fingerprint); k == nil || !k.Revoked {
		t.Errorf("old agent not revoked: %+v", k)
	}

	// Candidate states and audit.
	var st string
	pool.QueryRow(ctx, `SELECT status FROM device_merge_candidates WHERE id = $1`, candID).Scan(&st)
	if st != "confirmed" {
		t.Errorf("candidate: %s", st)
	}
	pool.QueryRow(ctx, `SELECT status FROM device_merge_candidates WHERE id = $1`, sideID).Scan(&st)
	if st != "rejected" {
		t.Errorf("other candidate of the merged record: %s, want rejected (superseded)", st)
	}
	var audits int
	pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'device.merge' AND target_id::text = $1
		AND details->>'from_device_uuid' = $2`, old.uuid, fresh.uuid).Scan(&audits)
	if audits != 1 {
		t.Errorf("merge audits: %d", audits)
	}
	if _, err := h.merge(ctx, DecideRequest{ID: candID}, actor, client); !isConflict(err) {
		t.Errorf("second confirm: %v", err)
	}

	// Reject leaves both records alone.
	a := seedDevice(t, pool, "PC-A-"+rnd(), "", 0)
	b := seedDevice(t, pool, "PC-B-"+rnd(), "", 0)
	rejID := candidate(t, pool, a, b)
	if _, err := h.reject(ctx, DecideRequest{ID: rejID, Reason: "different machines"}, actor, client); err != nil {
		t.Fatal(err)
	}
	var aStatus string
	pool.QueryRow(ctx, `SELECT status FROM devices WHERE id = $1`, a.uuid).Scan(&aStatus)
	pool.QueryRow(ctx, `SELECT status FROM device_merge_candidates WHERE id = $1`, rejID).Scan(&st)
	if aStatus != "active" || st != "rejected" {
		t.Errorf("reject: device %s, candidate %s", aStatus, st)
	}
}

func isConflict(err error) bool {
	var c errConflict
	return errors.As(err, &c)
}

func nowMinus(minutes int) time.Time  { return time.Now().Add(-time.Duration(minutes) * time.Minute) }
func nowMinusDays(days int) time.Time { return time.Now().AddDate(0, 0, -days) }
