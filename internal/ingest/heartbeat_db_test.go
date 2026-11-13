package ingest

// Integration test; skipped unless AEGIS_TEST_DATABASE_URL points at a throwaway
// database with all migrations applied. Creates its own rows, deletes nothing.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHeartbeatRenameAuditDB(t *testing.T) {
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

	b := make([]byte, 8)
	rand.Read(b)
	k := &identity.Known{DeviceID: "dev-" + hex.EncodeToString(b)}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (hostname, os_family, agent_reported_id) VALUES ('PC-1', 'windows', $1) RETURNING id`,
		k.DeviceID).Scan(&k.DeviceUUID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agents (device_id, agent_version, install_method) VALUES ($1, '1.0', 'unknown') RETURNING id`,
		k.DeviceUUID).Scan(&k.AgentUUID); err != nil {
		t.Fatal(err)
	}

	s := New(pool)
	for _, host := range []string{"PC-1", "PC-2", "PC-2", "", "PC-3"} { // "" = agent sent none: keep PC-2
		if err := s.Heartbeat(ctx, k, &aegisonev1.Heartbeat{Hostname: host}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := pool.Query(ctx, `SELECT details->>'message' FROM audit_log
		WHERE action = 'device.rename' AND target_id::text = $1 ORDER BY id`, k.DeviceUUID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var m string
		rows.Scan(&m)
		got = append(got, m)
	}
	want := []string{"Device renamed from PC-1 to PC-2", "Device renamed from PC-2 to PC-3"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("rename audits = %q, want %q", got, want)
	}
}
