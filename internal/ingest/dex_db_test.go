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
	w := NewDexWriter(pool, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
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
	crashOld, crashNew := time.Now().Add(-3*24*time.Hour).Truncate(time.Second), time.Now().Add(-1*time.Hour).Truncate(time.Second)
	inv := &aegisonev1.FullInventoryReport{
		CollectedAt: time.Now().Unix(),
		Identity:    &aegisonev1.IdentityInfo{LoggedOnUser: `CORP\alice`, MachineDomain: "CORP", DomainJoined: true, BootTime: boot.Unix()},
		DexHealth: &aegisonev1.DexHealth{WindowDays: 7, UnexpectedShutdowns: 2, Bugchecks: 1, AppCrashes: 5, AppHangs: 1, BootDurationMs: 42000,
			AppFaults: []*aegisonev1.AppFault{
				// Duplicate app: larger counts win, the most recent crash's detail wins.
				{Name: "outlook.exe", Crashes: 3, LastModule: "mso.dll", LastException: "0xc0000005", LastCrashUnix: crashOld.Unix()},
				{Name: "outlook.exe", Crashes: 4, Hangs: 1, LastModule: "ntdll.dll", LastException: "0xc0000409", LastCrashUnix: crashNew.Unix()},
				// Old agent: no detail. Future timestamp: dropped.
				{Name: "teams.exe", Crashes: 1, LastCrashUnix: time.Now().Add(48 * time.Hour).Unix()}, {Name: " "}}},
		AntivirusProducts: []*aegisonev1.AntivirusProduct{
			{Name: "Windows Defender", Enabled: true, UpToDate: true, ProductState: 0x61000},
			{Name: "Acme Endpoint Security", Enabled: false, UpToDate: false, ProductState: 0x40010},
			{Name: "Acme Endpoint Security", Enabled: true}, // duplicate name: first wins
			{Name: " "},
		},
	}
	sum, err := s.FullInventory(ctx, k, inv)
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Identity || !sum.DexHealth || sum.AppFaults != 2 || sum.Antivirus != 2 {
		t.Errorf("summary %+v", sum)
	}
	var module, exception *string
	var lastCrash *time.Time
	pool.QueryRow(ctx, `SELECT last_module, last_exception, last_crash_at FROM device_app_faults WHERE device_id = $1 AND app_name = 'outlook.exe'`, k.DeviceUUID).
		Scan(&module, &exception, &lastCrash)
	if module == nil || *module != "ntdll.dll" || exception == nil || *exception != "0xc0000409" || lastCrash == nil || !lastCrash.Equal(crashNew) {
		t.Errorf("outlook crash detail: %v %v %v", module, exception, lastCrash)
	}
	pool.QueryRow(ctx, `SELECT last_module, last_crash_at FROM device_app_faults WHERE device_id = $1 AND app_name = 'teams.exe'`, k.DeviceUUID).Scan(&module, &lastCrash)
	if module != nil || lastCrash != nil {
		t.Errorf("teams crash detail should be NULL: %v %v", module, lastCrash)
	}
	var avRows int
	var avProduct string
	var realtime bool
	var defenderState int64
	pool.QueryRow(ctx, `SELECT count(*) FROM device_antivirus_products WHERE device_id = $1`, k.DeviceUUID).Scan(&avRows)
	pool.QueryRow(ctx, `SELECT product_state FROM device_antivirus_products WHERE device_id = $1 AND name = 'Windows Defender'`, k.DeviceUUID).Scan(&defenderState)
	pool.QueryRow(ctx, `SELECT av_product, av_realtime_enabled FROM device_security_posture WHERE device_id = $1`, k.DeviceUUID).Scan(&avProduct, &realtime)
	if avRows != 2 || defenderState != 0x61000 || avProduct != "Windows Defender" || !realtime {
		t.Errorf("antivirus: rows %d defender state %#x posture %q realtime %v", avRows, defenderState, avProduct, realtime)
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
	// No antivirus list in the second report = not collected: rows kept.
	pool.QueryRow(ctx, `SELECT count(*) FROM device_antivirus_products WHERE device_id = $1`, k.DeviceUUID).Scan(&avRows)
	if avRows != 2 {
		t.Errorf("antivirus rows after a report without the section: %d, want 2", avRows)
	}
}

func TestDexExtendedDB(t *testing.T) {
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

	w := NewDexWriter(pool, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	w.Add(k, &aegisonev1.DexTelemetry{CollectedAt: at.Unix(), SampleCount: 20, CpuAvg: 10, MemUsedAvg: 40,
		DiskQueueAvg: 0.5, DiskIopsAvg: 100, DiskLatencyMsAvg: 3, NetTarget: "192.168.1.1", NetRttMsAvg: 1.5, NetLossPct: 10,
		BatteryPresent: true, BatteryAcOnline: false, BatteryChargePctAvg: 80, WifiPresent: true, WifiConnected: true,
		WifiSignalPctAvg: 65, WifiSsid: "CorpWiFi", BatteryHealthPct: 87.5, BatteryCycleCount: 312})
	stop()
	<-done

	var iops, rtt, loss, batt, sig, health float32
	var cycles int
	var bp, ac, wc bool
	var target, ssid string
	if err := pool.QueryRow(ctx, `SELECT disk_iops_avg, net_rtt_ms_avg, net_loss_pct, battery_pct_avg, wifi_signal_pct_avg,
		battery_present, battery_ac_online, wifi_connected, net_target, wifi_ssid, battery_health_pct, battery_cycle_count
		FROM device_dex_metrics WHERE device_id = $1`, k.DeviceUUID).
		Scan(&iops, &rtt, &loss, &batt, &sig, &bp, &ac, &wc, &target, &ssid, &health, &cycles); err != nil {
		t.Fatal(err)
	}
	if iops != 100 || rtt != 1.5 || loss != 10 || batt != 80 || sig != 65 || !bp || ac || !wc || target != "192.168.1.1" || ssid != "CorpWiFi" ||
		health != 87.5 || cycles != 312 {
		t.Errorf("row: iops=%v rtt=%v loss=%v batt=%v sig=%v bp=%v ac=%v wc=%v target=%s ssid=%s health=%v cycles=%d",
			iops, rtt, loss, batt, sig, bp, ac, wc, target, ssid, health, cycles)
	}
	// An older agent (no health fields) stores NULL, not 0.
	w2 := NewDexWriter(pool, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	runCtx2, stop2 := context.WithCancel(ctx)
	done2 := make(chan struct{})
	go func() { w2.Run(runCtx2); close(done2) }()
	w2.Add(k, &aegisonev1.DexTelemetry{CollectedAt: at.Add(5 * time.Minute).Unix(), SampleCount: 20, CpuAvg: 10, MemUsedAvg: 40, BatteryPresent: true, BatteryChargePctAvg: 79})
	stop2()
	<-done2
	var nullHealth *float32
	var nullCycles *int
	if err := pool.QueryRow(ctx, `SELECT battery_health_pct, battery_cycle_count FROM device_dex_metrics WHERE device_id = $1 AND time = $2`,
		k.DeviceUUID, at.Add(5*time.Minute)).Scan(&nullHealth, &nullCycles); err != nil {
		t.Fatal(err)
	}
	if nullHealth != nil || nullCycles != nil {
		t.Errorf("unknown battery health stored as %v / %v, want NULL", nullHealth, nullCycles)
	}
}
