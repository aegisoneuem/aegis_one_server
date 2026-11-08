package ingest

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5"
)

// Caps on one report, so a broken or hostile agent can't flood the database.
// Real devices are far below these (a busy workstation has a few hundred apps
// and drivers).
const (
	maxKBs     = 5000
	maxApps    = 10000
	maxDrivers = 10000
	maxAppx    = 5000
	maxDisks   = 256
	maxNICs    = 256
	maxIPs     = 64 // per NIC
	maxText    = 1024
)

// InventorySummary says what one report changed, for the log line.
type InventorySummary struct {
	KBs, Apps, AppsAdded, AppsRemoved, Drivers, Appx, Disks, NICs int
}

var kbRe = regexp.MustCompile(`^KB[0-9]{4,8}$`)

// NormalizeKB maps "kb5034441" / "5034441" / " KB5034441 " to "KB5034441";
// anything else is "".
func NormalizeKB(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "KB") {
		s = "KB" + s
	}
	if !kbRe.MatchString(s) {
		return ""
	}
	return s
}

// installedKBs replaces the device's installed update set. An empty list means
// the agent didn't report one (proto3 can't tell "none" from "absent", and a
// Windows box always has some), so the stored set is left alone.
func (s *Store) installedKBs(ctx context.Context, tx pgx.Tx, deviceUUID string, kbs []string) (int, error) {
	set := map[string]bool{}
	for _, k := range kbs {
		if k = NormalizeKB(k); k != "" {
			set[k] = true
		}
	}
	if len(set) == 0 {
		return 0, nil
	}
	if len(set) > maxKBs {
		return 0, fmt.Errorf("installed_kbs: %d entries is over the %d limit", len(set), maxKBs)
	}
	list := make([]string, 0, len(set))
	for k := range set {
		list = append(list, k)
	}
	sort.Strings(list)
	if _, err := tx.Exec(ctx, `DELETE FROM device_installed_kbs WHERE device_id = $1 AND NOT (kb = ANY($2))`, deviceUUID, list); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_installed_kbs (device_id, kb, reported_at)
		SELECT $1, unnest($2::text[]), now()
		ON CONFLICT (device_id, kb) DO UPDATE SET reported_at = now()`, deviceUUID, list); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET installed_kbs_at = now() WHERE id = $1`, deviceUUID); err != nil {
		return 0, err
	}
	return len(list), nil
}

// installedApps syncs software_inventory with the agent's list: present apps
// are upserted (and un-removed), apps no longer reported get removed_at, and
// the difference goes to inventory_change_log (not on the first report, which
// would log every app as "installed"). An empty list is "not reported".
func (s *Store) installedApps(ctx context.Context, tx pgx.Tx, deviceUUID string, apps []*aegisonev1.InstalledApp, sum *InventorySummary) error {
	if len(apps) == 0 {
		return nil
	}
	if len(apps) > maxApps {
		return fmt.Errorf("installed_apps: %d entries is over the %d limit", len(apps), maxApps)
	}
	type key struct{ name, version string }
	seen := map[key]bool{}
	var names, versions, publishers, keys, hives, uninstall []string
	var dates []*time.Time
	var sizes []*int64
	for _, a := range apps {
		k := key{clip(a.GetDisplayName()), clip(a.GetDisplayVersion())}
		if k.name == "" || seen[k] {
			continue
		}
		seen[k] = true
		names, versions = append(names, k.name), append(versions, k.version)
		publishers = append(publishers, clip(a.GetPublisher()))
		keys, hives = append(keys, clip(a.GetUninstallKey())), append(hives, clip(a.GetHive()))
		uninstall = append(uninstall, clip(a.GetUninstallString()))
		dates = append(dates, parseDate(a.GetInstallDate()))
		var size *int64
		if n := a.GetEstimatedSizeKb(); n > 0 {
			size = &n
		}
		sizes = append(sizes, size)
	}

	rows, err := tx.Query(ctx, `SELECT app_name, coalesce(app_version, '') FROM software_inventory WHERE device_id = $1 AND removed_at IS NULL`, deviceUUID)
	if err != nil {
		return err
	}
	before := map[key]bool{}
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.name, &k.version); err != nil {
			rows.Close()
			return err
		}
		before[k] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO software_inventory (device_id, app_name, app_version, publisher, install_date,
		                                uninstall_key, hive, estimated_size_kb, uninstall_string, detected_at)
		SELECT $1, n, v, NULLIF(p, ''), d, NULLIF(k, ''), NULLIF(h, ''), sz, NULLIF(u, ''), now()
		FROM unnest($2::text[], $3::text[], $4::text[], $5::date[], $6::text[], $7::text[], $8::bigint[], $9::text[])
		     AS t(n, v, p, d, k, h, sz, u)
		ON CONFLICT (device_id, app_name, app_version) DO UPDATE SET
		    publisher = EXCLUDED.publisher, install_date = EXCLUDED.install_date,
		    uninstall_key = EXCLUDED.uninstall_key, hive = EXCLUDED.hive,
		    estimated_size_kb = EXCLUDED.estimated_size_kb, uninstall_string = EXCLUDED.uninstall_string,
		    removed_at = NULL,
		    detected_at = CASE WHEN software_inventory.removed_at IS NULL THEN software_inventory.detected_at ELSE now() END`,
		deviceUUID, names, versions, publishers, dates, keys, hives, sizes, uninstall); err != nil {
		return fmt.Errorf("upsert software_inventory: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE software_inventory SET removed_at = now()
		WHERE device_id = $1 AND removed_at IS NULL
		  AND (app_name, coalesce(app_version, '')) NOT IN (SELECT * FROM unnest($2::text[], $3::text[]))`,
		deviceUUID, names, versions); err != nil {
		return fmt.Errorf("mark removed software: %w", err)
	}

	var changeTypes, changeNames, changeVersions []string
	for k := range seen {
		if !before[k] {
			sum.AppsAdded++
			changeTypes, changeNames, changeVersions = append(changeTypes, "software_installed"), append(changeNames, k.name), append(changeVersions, k.version)
		}
	}
	for k := range before {
		if !seen[k] {
			sum.AppsRemoved++
			changeTypes, changeNames, changeVersions = append(changeTypes, "software_removed"), append(changeNames, k.name), append(changeVersions, k.version)
		}
	}
	sum.Apps = len(seen)
	if len(before) > 0 && len(changeTypes) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO inventory_change_log (device_id, change_type, details)
			SELECT $1, t, jsonb_build_object('app_name', n, 'app_version', v)
			FROM unnest($2::text[], $3::text[], $4::text[]) AS x(t, n, v)`,
			deviceUUID, changeTypes, changeNames, changeVersions); err != nil {
			return fmt.Errorf("insert inventory_change_log: %w", err)
		}
	}
	return nil
}

// FullInventory saves the agent's periodic full snapshot: hardware on the
// device row, and disks, NICs/IPs, apps, drivers and appx packages as child
// rows (each list replaces what was stored). An empty list leaves its table
// alone, since proto3 can't tell "none" from "not collected".
func (s *Store) FullInventory(ctx context.Context, known *identity.Known, inv *aegisonev1.FullInventoryReport) (InventorySummary, error) {
	var sum InventorySummary
	if n := len(inv.GetDrivers()); n > maxDrivers {
		return sum, fmt.Errorf("drivers: %d entries is over the %d limit", n, maxDrivers)
	}
	if n := len(inv.GetInstalledAppx()); n > maxAppx {
		return sum, fmt.Errorf("installed_appx: %d entries is over the %d limit", n, maxAppx)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sum, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	dev := known.DeviceUUID

	if hw := inv.GetHardware(); hw != nil {
		if err := hardware(ctx, tx, dev, hw, &sum); err != nil {
			return sum, err
		}
	}
	if err := s.installedApps(ctx, tx, dev, inv.GetInstalledApps(), &sum); err != nil {
		return sum, err
	}
	if drv := inv.GetDrivers(); len(drv) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM device_drivers WHERE device_id = $1`, dev); err != nil {
			return sum, err
		}
		rows := make([][]any, 0, len(drv))
		for _, d := range drv {
			if clip(d.GetDeviceName()) == "" || clip(d.GetDriverVersion()) == "" {
				continue // the agent drops these too; a row with no version can't be compared
			}
			rows = append(rows, []any{dev, clip(d.GetDeviceName()), nullable(d.GetDeviceClass()), clip(d.GetDriverVersion()),
				parseDate(d.GetDriverDate()), nullable(d.GetProviderName()), nullable(d.GetHardwareId()), nullable(d.GetInfName()),
				nullable(d.GetManufacturer()), d.GetIsSigned()})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"device_drivers"},
			[]string{"device_id", "device_name", "device_class", "driver_version", "driver_date", "provider_name",
				"hardware_id", "inf_name", "manufacturer", "is_signed"}, pgx.CopyFromRows(rows)); err != nil {
			return sum, fmt.Errorf("copy device_drivers: %w", err)
		}
		sum.Drivers = len(rows)
	}
	if appx := inv.GetInstalledAppx(); len(appx) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM device_appx_packages WHERE device_id = $1`, dev); err != nil {
			return sum, err
		}
		seen := map[string]bool{}
		rows := make([][]any, 0, len(appx))
		for _, a := range appx {
			full := clip(a.GetPackageFullName())
			if full == "" || seen[full] {
				continue
			}
			seen[full] = true
			rows = append(rows, []any{dev, full, nullable(a.GetPackageFamilyName()), nullable(a.GetName()), nullable(a.GetDisplayName()),
				nullable(a.GetVersion()), nullable(a.GetArchitecture()), nullable(a.GetPublisherId()), nullable(a.GetInstallLocation()),
				nullable(a.GetOrigin())})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"device_appx_packages"},
			[]string{"device_id", "package_full_name", "package_family_name", "name", "display_name", "version",
				"architecture", "publisher_id", "install_location", "origin"}, pgx.CopyFromRows(rows)); err != nil {
			return sum, fmt.Errorf("copy device_appx_packages: %w", err)
		}
		sum.Appx = len(rows)
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET last_inventory_at = now() WHERE id = $1`, dev); err != nil {
		return sum, err
	}
	return sum, tx.Commit(ctx)
}

// hardware saves HardwareInventory on the device row (empty fields keep the
// old value) and replaces its disks and network interfaces.
func hardware(ctx context.Context, tx pgx.Tx, dev string, hw *aegisonev1.HardwareInventory, sum *InventorySummary) error {
	var ramGB *float64
	if b := hw.GetMemoryTotalBytes(); b > 0 {
		v := math.Round(float64(b)/(1<<30)*100) / 100
		ramGB = &v
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET
		    cpu_vendor         = coalesce($2, cpu_vendor),
		    cpu_model          = coalesce($3, cpu_model),
		    cpu_physical_cores = coalesce($4, cpu_physical_cores),
		    cpu_logical_cores  = coalesce($5, cpu_logical_cores),
		    ram_gb             = coalesce($6, ram_gb),
		    bios_vendor        = coalesce($7, bios_vendor),
		    bios_version       = coalesce($8, bios_version),
		    bios_release_date  = coalesce($9, bios_release_date),
		    manufacturer       = coalesce($10, manufacturer),
		    model              = coalesce($11, model),
		    serial_tag         = coalesce($12, serial_tag),
		    chassis_type       = coalesce($13, chassis_type),
		    virtualization     = coalesce($14, virtualization),
		    smbios_uuid        = coalesce($15, smbios_uuid),
		    updated_at         = now()
		WHERE id = $1`,
		dev, nullable(hw.GetCpuVendor()), nullable(hw.GetCpuModel()), positive(hw.GetCpuPhysicalCores()), positive(hw.GetCpuLogicalCores()),
		ramGB, nullable(hw.GetBiosVendor()), nullable(hw.GetBiosVersion()), parseDate(hw.GetBiosReleaseDate()),
		nullable(hw.GetSystemVendor()), nullable(hw.GetSystemProduct()), nullable(hw.GetSystemSerialNumber()),
		nullable(hw.GetChassisType()), nullable(hw.GetVirtualization()), nullable(hw.GetSystemUuid())); err != nil {
		return fmt.Errorf("update device hardware: %w", err)
	}

	if disks := hw.GetDisks(); len(disks) > 0 {
		if len(disks) > maxDisks {
			return fmt.Errorf("disks: %d entries is over the %d limit", len(disks), maxDisks)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM device_disks WHERE device_id = $1`, dev); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, d := range disks {
			mp := clip(d.GetMountPoint())
			if mp == "" || seen[mp] {
				continue
			}
			seen[mp] = true
			if _, err := tx.Exec(ctx, `
				INSERT INTO device_disks (device_id, mount_point, filesystem, size_gb, free_gb)
				VALUES ($1, $2, $3, $4, $5)`,
				dev, mp, nullable(d.GetFileSystem()), gib(d.GetTotalBytes()), gib(d.GetFreeBytes())); err != nil {
				return fmt.Errorf("insert device_disks: %w", err)
			}
			sum.Disks++
		}
	}

	if nics := hw.GetNics(); len(nics) > 0 {
		if len(nics) > maxNICs {
			return fmt.Errorf("nics: %d entries is over the %d limit", len(nics), maxNICs)
		}
		// IP rows go with their interface (FK cascade) but are keyed per device,
		// so clear both.
		if _, err := tx.Exec(ctx, `DELETE FROM device_ip_addresses WHERE device_id = $1`, dev); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM device_network_interfaces WHERE device_id = $1`, dev); err != nil {
			return err
		}
		seenNIC, seenIP := map[string]bool{}, map[netip.Addr]bool{}
		for _, n := range nics {
			name := clip(n.GetName())
			if name == "" || seenNIC[name] {
				continue
			}
			seenNIC[name] = true
			var mac *string
			if parsed, err := net.ParseMAC(strings.TrimSpace(n.GetMacAddress())); err == nil {
				m := parsed.String()
				mac = &m
			}
			var speed *int32
			if bps := n.GetLinkSpeedBps(); bps > 0 && bps/1_000_000 <= math.MaxInt32 {
				v := int32(bps / 1_000_000)
				speed = &v
			}
			var up *bool
			if st := strings.TrimSpace(n.GetStatus()); st != "" {
				v := strings.EqualFold(st, "up") || strings.EqualFold(st, "connected")
				up = &v
			}
			var nicID string
			if err := tx.QueryRow(ctx, `
				INSERT INTO device_network_interfaces (device_id, name, mac_address, is_up, speed_mbps)
				VALUES ($1, $2, $3::macaddr, $4, $5) RETURNING id`, dev, name, mac, up, speed).Scan(&nicID); err != nil {
				return fmt.Errorf("insert device_network_interfaces: %w", err)
			}
			sum.NICs++
			ips := append(append([]string{}, n.GetIpv4Addresses()...), n.GetIpv6Addresses()...)
			if len(ips) > maxIPs {
				ips = ips[:maxIPs]
			}
			for _, raw := range ips {
				addr, ok := parseIP(raw)
				if !ok || seenIP[addr] {
					continue
				}
				seenIP[addr] = true
				if _, err := tx.Exec(ctx, `
					INSERT INTO device_ip_addresses (device_id, interface_id, ip) VALUES ($1, $2, $3::inet)`,
					dev, nicID, addr.String()); err != nil {
					return fmt.Errorf("insert device_ip_addresses: %w", err)
				}
			}
		}
	}
	return nil
}

// AuditEvent appends one agent audit event. A resent event (same device, ts,
// type and command) is ignored. Returns whether a row was added.
func (s *Store) AuditEvent(ctx context.Context, known *identity.Known, ev *aegisonev1.AuditEvent) (bool, error) {
	eventType := clip(ev.GetEventType())
	if eventType == "" {
		return false, fmt.Errorf("audit event without event_type")
	}
	ts := time.Now()
	if ms := ev.GetTs(); ms > 0 {
		ts = time.UnixMilli(ms)
	}
	var issued *time.Time
	if sec := ev.GetIssuedAt(); sec > 0 {
		t := time.Unix(sec, 0)
		issued = &t
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO agent_audit_events (device_id, agent_id, ts, event_type, command_id, command_type, actor, source,
		                                issued_at, signature_ok, decision, reason, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (device_id, ts, event_type, coalesce(command_id, '')) DO NOTHING`,
		known.DeviceUUID, known.AgentUUID, ts, eventType, nullable(ev.GetCommandId()), nullable(ev.GetCommandType()),
		nullable(ev.GetActor()), nullable(ev.GetSource()), issued, ev.GetSignatureOk(), nullable(ev.GetDecision()),
		nullable(ev.GetReason()), nullableN(ev.GetDetails(), 4096))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// clip trims s and cuts it to maxText bytes on a rune boundary.
func clip(s string) string { return clipN(s, maxText) }

func clipN(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func nullable(s string) *string { return nullableN(s, maxText) }

func nullableN(s string, n int) *string {
	if s = clipN(s, n); s == "" {
		return nil
	}
	return &s
}

func positive(n int32) *int32 {
	if n <= 0 {
		return nil
	}
	return &n
}

func gib(b int64) *float64 {
	if b <= 0 {
		return nil
	}
	v := math.Round(float64(b)/(1<<30)*100) / 100
	return &v
}

// parseDate reads the date formats the agent sends: registry InstallDate
// "20240315", WMI/ISO "2024-03-15", and SMBIOS "03/15/2024". Anything else
// (including empty) is nil.
func parseDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"20060102", "2006-01-02", "01/02/2006"} {
		if t, err := time.Parse(layout, s); err == nil && t.Year() >= 1980 && t.Year() <= 2100 {
			return &t
		}
	}
	return nil
}

// parseIP accepts "10.0.0.5", "10.0.0.5/24" and "fe80::1%12".
func parseIP(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().WithZone(""), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone(""), true
}
