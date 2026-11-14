package ingest

// Integration test; skipped unless AEGIS_TEST_DATABASE_URL points at a throwaway
// database with all migrations applied. Creates its own rows, deletes nothing.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5/pgxpool"
)

func dexTestDevice(t *testing.T, pool *pgxpool.Pool) *identity.Known {
	t.Helper()
	b := make([]byte, 8)
	rand.Read(b)
	k := &identity.Known{DeviceID: "dev-" + hex.EncodeToString(b)}
	if err := pool.QueryRow(context.Background(), `INSERT INTO devices (hostname, os_family, agent_reported_id) VALUES ('PC-DEX', 'windows', $1) RETURNING id`,
		k.DeviceID).Scan(&k.DeviceUUID); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDexDB(t *testing.T) {
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
	k := dexTestDevice(t, pool)

	// Telemetry: queued, written in one COPY on shutdown drain, in-batch repeat dropped.
	w := NewDexWriter(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i := 0; i < 3; i++ {
		w.Add(k, &aegisonev1.DexTelemetry{CollectedAt: base.Add(time.Duration(i) * 5 * time.Minute).Unix(), WindowSeconds: 300,
			SampleCount: 20, CpuAvg: float64(10 * (i + 1)), CpuMin: 1, CpuMax: 90, MemUsedAvg: 50, MemUsedMin: 40, MemUsedMax: 60})
	}
	w.Add(k, &aegisonev1.DexTelemetry{CollectedAt: base.Unix(), SampleCount: 20, CpuAvg: 10}) // resend
	w.Add(k, &aegisonev1.DexTelemetry{})                                                      // empty: ignored
	stop()
	<-done
	if w.Add(k, &aegisonev1.DexTelemetry{SampleCount: 1, CpuAvg: 1}) {
		t.Error("Add accepted after shutdown")
	}
	var n int
	var avg float64
	pool.QueryRow(ctx, `SELECT count(*), avg(cpu_pct) FROM device_dex_metrics WHERE device_id = $1`, k.DeviceUUID).Scan(&n, &avg)
	if n != 3 || avg != 20 {
		t.Errorf("dex rows = %d avg cpu %v, want 3 / 20", n, avg)
	}
	if written, _ := w.Stats(); written != 3 {
		t.Errorf("written = %d", written)
	}

	// Inventory identity + dex_health.
	s := New(pool)
	boot := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	inv := &aegisonev1.FullInventoryReport{
		CollectedAt: time.Now().Unix(),
		Identity:    &aegisonev1.IdentityInfo{LoggedOnUser: `CORP\alice`, MachineDomain: "CORP", DomainJoined: true, BootTime: boot.Unix()},
		DexHealth: &aegisonev1.DexHealth{WindowDays: 7, UnexpectedShutdowns: 2, Bugchecks: 1, AppCrashes: 5, AppHangs: 1, BootDurationMs: 42000,
			AppFaults: []*aegisonev1.AppFault{{Name: "outlook.exe", Crashes: 3}, {Name: "outlook.exe", Crashes: 4, Hangs: 1}, {Name: "teams.exe", Crashes: 1}, {Name: " "}}},
	}
	sum, err := s.FullInventory(ctx, k, inv)
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Identity || !sum.DexHealth || sum.AppFaults != 2 {
		t.Errorf("summary %+v", sum)
	}
	var user, domain string
	var joined bool
	var lastBoot time.Time
	pool.QueryRow(ctx, `SELECT last_logged_on_user, domain_name, is_domain_joined, last_boot_at FROM devices WHERE id = $1`, k.DeviceUUID).
		Scan(&user, &domain, &joined, &lastBoot)
	if user != `CORP\alice` || domain != "CORP" || !joined || !lastBoot.Equal(boot) {
		t.Errorf("identity: %s %s %v %v", user, domain, joined, lastBoot)
	}
	var crashes, hangs int
	pool.QueryRow(ctx, `SELECT crashes, hangs FROM device_app_faults WHERE device_id = $1 AND app_name = 'outlook.exe'`, k.DeviceUUID).Scan(&crashes, &hangs)
	if crashes != 4 || hangs != 1 {
		t.Errorf("outlook faults %d/%d, want 4/1", crashes, hangs)
	}

	// Next report: nobody logged on, join state unreadable, no faults -> user and
	// domain kept, faults cleared, snapshot replaced.
	inv2 := &aegisonev1.FullInventoryReport{CollectedAt: time.Now().Unix(), Identity: &aegisonev1.IdentityInfo{},
		DexHealth: &aegisonev1.DexHealth{WindowDays: 7, AppCrashes: 0}}
	if _, err := s.FullInventory(ctx, k, inv2); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, `SELECT last_logged_on_user, domain_name, is_domain_joined FROM devices WHERE id = $1`, k.DeviceUUID).Scan(&user, &domain, &joined)
	var faults, shutdowns int
	pool.QueryRow(ctx, `SELECT count(*) FROM device_app_faults WHERE device_id = $1`, k.DeviceUUID).Scan(&faults)
	pool.QueryRow(ctx, `SELECT unexpected_shutdowns FROM device_dex_health WHERE device_id = $1`, k.DeviceUUID).Scan(&shutdowns)
	if user != `CORP\alice` || domain != "CORP" || !joined || faults != 0 || shutdowns != 0 {
		t.Errorf("second report: user=%s domain=%s joined=%v faults=%d shutdowns=%d", user, domain, joined, faults, shutdowns)
	}
}
