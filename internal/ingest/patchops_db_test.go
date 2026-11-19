package ingest

// Integration test; skipped unless AEGIS_TEST_DATABASE_URL points at a throwaway
// database with all migrations applied. Creates its own rows, deletes nothing.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/kev"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func randomKB() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	return "KB" + strconv.FormatInt(7000000+n.Int64(), 10)
}

func TestScanRunsAndCacheFullDB(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	s := New(pool)
	k := dexTestDevice(t, pool)
	now := time.Now().Unix()

	// A failed cab scan, then a later successful one; a late, older failure
	// arriving afterwards doesn't overwrite the device's last scan.
	fail := &aegisonev1.ActionStatus{ActionId: "scan-" + strconv.FormatInt(now-600, 10), ActionType: "scan",
		Phase: aegisonev1.ActionPhase_ACTION_PHASE_FAILED, Reason: "scan failed: 0x80240440", StartedAt: now - 600, FinishedAt: now - 590}
	if !IsScanRun(fail) {
		t.Fatal("scan status not recognized")
	}
	ok := &aegisonev1.ActionStatus{ActionId: "scan-" + strconv.FormatInt(now-60, 10), ActionType: "scan",
		Phase: aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS, Reason: "3 missing, 1 superseded, 200 installed", StartedAt: now - 60, FinishedAt: now - 30}
	for _, st := range []*aegisonev1.ActionStatus{ok, fail} {
		if err := s.ScanRun(ctx, k, st); err != nil {
			t.Fatal(err)
		}
	}
	var runs int
	var status, reason string
	pool.QueryRow(ctx, `SELECT count(*) FROM device_patch_scan_runs WHERE device_id = $1`, k.DeviceUUID).Scan(&runs)
	pool.QueryRow(ctx, `SELECT last_cab_scan_status, last_cab_scan_reason FROM devices WHERE id = $1`, k.DeviceUUID).Scan(&status, &reason)
	if runs != 2 || status != "succeeded" || reason != ok.Reason {
		t.Errorf("runs %d, last scan %s %q", runs, status, reason)
	}
	var failReason string
	pool.QueryRow(ctx, `SELECT reason FROM device_patch_scan_runs WHERE device_id = $1 AND status = 'failed'`, k.DeviceUUID).Scan(&failReason)
	if failReason != fail.Reason {
		t.Errorf("failed scan reason %q", failReason)
	}

	// Cache full: device columns + one open alert; a repeat bumps it; a staged
	// patch resolves it.
	cf := &aegisonev1.CacheFullReport{PendingId: "abc", NeededBytes: 900 << 20, CapBytes: 2 << 30, InUseBytes: 1900 << 20, Message: "patch cache full"}
	for i := 0; i < 2; i++ {
		if err := s.CacheFull(ctx, k, cf); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	var capBytes int64
	pool.QueryRow(ctx, `SELECT occurrence_count FROM alerts WHERE dedup_key = $1 AND status = 'open'`, CacheFullAlertKey(k.DeviceUUID)).Scan(&count)
	pool.QueryRow(ctx, `SELECT patch_cache_cap_bytes FROM devices WHERE id = $1 AND patch_cache_full_at IS NOT NULL`, k.DeviceUUID).Scan(&capBytes)
	if count != 2 || capBytes != 2<<30 {
		t.Errorf("cache full: alert count %d, cap %d", count, capBytes)
	}
	if resolved, err := s.CacheRecovered(ctx, k); err != nil || !resolved {
		t.Fatalf("recovered: %v %v", resolved, err)
	}
	var open int
	pool.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE dedup_key = $1 AND status <> 'resolved'`, CacheFullAlertKey(k.DeviceUUID)).Scan(&open)
	if open != 0 {
		t.Error("cache-full alert still open")
	}
}

func TestPendingRebootKBsDB(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	s := New(pool)
	k := dexTestDevice(t, pool)
	kb := randomKB()
	var patchID string
	if err := pool.QueryRow(ctx, `INSERT INTO patch_catalog (vendor, product, kb_or_advisory_id, title) VALUES ('microsoft', 'Windows', $1, 't') RETURNING id`,
		kb).Scan(&patchID); err != nil {
		t.Fatal(err)
	}
	pool.Exec(ctx, `INSERT INTO device_patch_state (device_id, patch_id, state, detection_source) VALUES ($1, $2, 'missing', 'agent_wua')`, k.DeviceUUID, patchID)

	ds := &aegisonev1.DeviceStateReport{Build: "26100.4652", RebootPending: true, RebootPendingSources: []string{"cbs"},
		RebootPendingKbs: []string{kb[2:], kb, "garbage"}}
	sum, err := s.DeviceState(ctx, k, ds)
	if err != nil {
		t.Fatal(err)
	}
	var kbs []string
	var state string
	pool.QueryRow(ctx, `SELECT pending_reboot_kbs FROM devices WHERE id = $1`, k.DeviceUUID).Scan(&kbs)
	pool.QueryRow(ctx, `SELECT state FROM device_patch_state WHERE device_id = $1 AND patch_id = $2`, k.DeviceUUID, patchID).Scan(&state)
	if sum.PendingRebootKBs != 1 || len(kbs) != 1 || kbs[0] != kb || state != "pending_reboot" {
		t.Errorf("pending: sum %d kbs %v state %s", sum.PendingRebootKBs, kbs, state)
	}
	// Rebooted: the list empties.
	if _, err := s.DeviceState(ctx, k, &aegisonev1.DeviceStateReport{Build: "26100.4700"}); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, `SELECT pending_reboot_kbs FROM devices WHERE id = $1`, k.DeviceUUID).Scan(&kbs)
	if len(kbs) != 0 {
		t.Errorf("after reboot: %v", kbs)
	}
}

func TestPatchScanMetadataDB(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	s := New(pool)
	k := dexTestDevice(t, pool)
	newKB, oldKB, msrcKB := randomKB(), randomKB(), randomKB()
	b := make([]byte, 4)
	rand.Read(b)
	tag := hex.EncodeToString(b)
	// An MSRC row the agent must not rewrite.
	pool.Exec(ctx, `INSERT INTO patch_catalog (vendor, product, kb_or_advisory_id, title, description) VALUES ('microsoft', 'Windows', $1, 'msrc title', NULL)`, msrcKB)
	cve := "CVE-2026-" + strconv.Itoa(40000+int(b[0])*100+int(b[1]%100))

	psr := &aegisonev1.PatchScanResult{ProductName: "Windows 11", Build: "26100.4652", Missing: []*aegisonev1.MissingUpdate{
		{UpdateId: "new-" + tag, KbArticleIds: []string{newKB}, Title: "New update", Classification: "Security Updates",
			CveIds: []string{cve, "not-a-cve", cve}, SizeMb: 812.5, RebootRequired: true, RevisionNumber: 3,
			Description: "Fixes things", SupersededUpdateIds: []string{"OLD-" + tag, "msrc-" + tag},
			// An agent's rating and link are not trusted fleet-wide.
			MsrcSeverity: "Critical", SupportUrl: "https://attacker.example/" + newKB},
		{UpdateId: "old-" + tag, KbArticleIds: []string{oldKB}, Title: "Old update", Superseded: true,
			SupportUrl: "https://support.microsoft.com/help/" + strings.TrimPrefix(oldKB, "KB")},
		{UpdateId: "msrc-" + tag, KbArticleIds: []string{msrcKB}, Title: "x", Description: "agent text", SizeMb: 5},
		// Not a KB number: must not become a catalog row, goes to unmatched.
		{UpdateId: "junk-" + tag, KbArticleIds: []string{"KB" + tag + "-evil"}, Title: strings.Repeat("t", 3000), MsrcSeverity: "Critical"},
	}}
	sum, err := s.PatchScan(ctx, k, psr)
	if err != nil {
		t.Fatal(err)
	}
	var desc, reboot, severity, source string
	var vendorSev, articleURL *string
	var size float64
	var rev int
	pool.QueryRow(ctx, `SELECT description, download_size_mb, reboot_behavior, revision, severity, coalesce(catalog_source, ''), vendor_severity, kb_article_url
		FROM patch_catalog WHERE kb_or_advisory_id = $1`, newKB).
		Scan(&desc, &size, &reboot, &rev, &severity, &source, &vendorSev, &articleURL)
	if desc != "Fixes things" || size != 812.5 || reboot != "may" || rev != 3 {
		t.Errorf("agent row: %q %v %s %d", desc, size, reboot, rev)
	}
	// Unverified: the claimed "Critical" stays in vendor_severity only, and the
	// non-Microsoft link is dropped.
	if severity != "unrated" || source != "agent_report" || vendorSev == nil || *vendorSev != "Critical" || articleURL != nil {
		t.Errorf("agent row trust: severity %q source %q vendor %v url %v", severity, source, vendorSev, articleURL)
	}
	var oldURL *string
	pool.QueryRow(ctx, `SELECT kb_article_url FROM patch_catalog WHERE kb_or_advisory_id = $1`, oldKB).Scan(&oldURL)
	if oldURL == nil || !strings.HasPrefix(*oldURL, "https://support.microsoft.com/") {
		t.Errorf("Microsoft article link dropped: %v", oldURL)
	}
	var junkRows, unmatched int
	var unmatchedKB *string
	var unmatchedTitle string
	pool.QueryRow(ctx, `SELECT count(*) FROM patch_catalog WHERE kb_or_advisory_id LIKE 'KB' || $1 || '%'`, strings.ToUpper(tag)).Scan(&junkRows)
	pool.QueryRow(ctx, `SELECT count(*), max(kb_or_advisory_id), max(title) FROM unmatched_patch_reports WHERE device_id = $1 AND report_key = $2`,
		k.DeviceUUID, "wua:junk-"+tag).Scan(&unmatched, &unmatchedKB, &unmatchedTitle)
	if junkRows != 0 || unmatched != 1 || unmatchedKB != nil || len(unmatchedTitle) != 1024 {
		t.Errorf("junk KB: catalog rows %d unmatched %d kb %v title len %d", junkRows, unmatched, unmatchedKB, len(unmatchedTitle))
	}
	if sum.AgentCataloged != 2 || sum.Unmatched != 1 {
		t.Errorf("summary: cataloged %d unmatched %d", sum.AgentCataloged, sum.Unmatched)
	}
	// No SLA for an unverified row, even though the agent said "Critical".
	var sla *time.Time
	pool.QueryRow(ctx, `SELECT s.sla_due_at FROM device_patch_state s JOIN patch_catalog p ON p.id = s.patch_id
		WHERE s.device_id = $1 AND p.kb_or_advisory_id = $2`, k.DeviceUUID, newKB).Scan(&sla)
	if sla != nil {
		t.Errorf("unrated agent row got an SLA: %v", *sla)
	}
	var cves int
	var linkSource string
	pool.QueryRow(ctx, `SELECT count(*), max(pc.source) FROM patch_cves pc JOIN patch_catalog p ON p.id = pc.patch_id WHERE p.kb_or_advisory_id = $1`, newKB).Scan(&cves, &linkSource)
	if cves != 1 || linkSource != "agent_report" {
		t.Errorf("cve links %d (source %q), want 1 agent_report", cves, linkSource)
	}
	// Even if that CVE is on CISA KEV, the agent's link must not make the patch
	// known-exploited (and so must not give the unrated row the KEV SLA).
	pool.Exec(ctx, `UPDATE cve_catalog SET is_kev = true, kev_added_at = current_date WHERE cve_id = $1`, cve)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := kev.Apply(ctx, tx); err != nil {
		t.Fatalf("kev.Apply: %v", err)
	}
	if _, err := AssignSLA(ctx, tx, k.DeviceUUID); err != nil {
		t.Fatalf("AssignSLA: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var hasKEV bool
	pool.QueryRow(ctx, `SELECT has_kev FROM patch_catalog WHERE kb_or_advisory_id = $1`, newKB).Scan(&hasKEV)
	if hasKEV {
		t.Error("agent-reported CVE link flagged the patch has_kev")
	}
	pool.QueryRow(ctx, `SELECT s.sla_due_at FROM device_patch_state s JOIN patch_catalog p ON p.id = s.patch_id
		WHERE s.device_id = $1 AND p.kb_or_advisory_id = $2`, k.DeviceUUID, newKB).Scan(&sla)
	if sla != nil {
		t.Errorf("planted KEV link gave the unrated row an SLA: %v", *sla)
	}
	var msrcDesc *string
	var msrcSize *float64
	pool.QueryRow(ctx, `SELECT description, download_size_mb FROM patch_catalog WHERE kb_or_advisory_id = $1`, msrcKB).Scan(&msrcDesc, &msrcSize)
	if msrcDesc != nil || msrcSize != nil {
		t.Errorf("MSRC row rewritten by the agent: %v %v", msrcDesc, msrcSize)
	}
	// new supersedes old (both agent-reported); never the MSRC row.
	if sum.SupersedenceLinks != 1 {
		t.Errorf("supersedence links %d, want 1", sum.SupersedenceLinks)
	}
}

func TestHardwareDetailDB(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	s := New(pool)
	k := dexTestDevice(t, pool)
	inv := &aegisonev1.FullInventoryReport{CollectedAt: time.Now().Unix(), Hardware: &aegisonev1.HardwareInventory{
		CpuModel: "Xeon", CpuMhz: 2900, CpuThreadsPerCore: 2, CpuArchitecture: "x64", OsProductName: "Windows 11 Enterprise",
		OsDisplayVersion: "24H2", OsBuild: "26100.4652", OsServicePack: "",
		Disks: []*aegisonev1.DiskInventory{{MountPoint: "C:", VolumeLabel: "OS", FileSystem: "NTFS", TotalBytes: 500 << 30, FreeBytes: 100 << 30, DriveType: "fixed"}},
	}}
	if _, err := s.FullInventory(ctx, k, inv); err != nil {
		t.Fatal(err)
	}
	var mhz, tpc, ubr int
	var arch, edition, version, build, label, dtype string
	var sp *string
	pool.QueryRow(ctx, `SELECT cpu_mhz, cpu_threads_per_core, cpu_architecture, os_service_pack, os_edition, os_version, os_build, os_ubr
		FROM devices WHERE id = $1`, k.DeviceUUID).Scan(&mhz, &tpc, &arch, &sp, &edition, &version, &build, &ubr)
	pool.QueryRow(ctx, `SELECT volume_label, drive_type FROM device_disks WHERE device_id = $1`, k.DeviceUUID).Scan(&label, &dtype)
	if mhz != 2900 || tpc != 2 || arch != "x64" || sp != nil || edition != "Windows 11 Enterprise" || version != "24H2" ||
		build != "26100" || ubr != 4652 || label != "OS" || dtype != "fixed" {
		t.Errorf("hardware: %d %d %s %v %s %s %s %d %s %s", mhz, tpc, arch, sp, edition, version, build, ubr, label, dtype)
	}
	// The fast-lane report owns the build: a later inventory doesn't move it back.
	pool.Exec(ctx, `UPDATE devices SET os_ubr = 4700 WHERE id = $1`, k.DeviceUUID)
	if _, err := s.FullInventory(ctx, k, inv); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, `SELECT os_ubr FROM devices WHERE id = $1`, k.DeviceUUID).Scan(&ubr)
	if ubr != 4700 {
		t.Errorf("inventory overwrote the UBR: %d", ubr)
	}
}
