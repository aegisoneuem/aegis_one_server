// Package compliance reads the compliance views already defined in
// db/migrations (device_patch_compliance_current, patch_compliance_by_patch) -
// it adds no new SQL logic of its own, just typed Go access to those views.
package compliance

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PatchRow is one row of patch_compliance_by_patch: "which patches are hurting
// us most" - how many devices have each patch missing vs. installed.
type PatchRow struct {
	KB               string `json:"kb"`
	Title            string `json:"title"`
	Severity         string `json:"severity"`
	HasKEV           bool   `json:"has_kev"`
	DevicesInstalled int    `json:"devices_installed"`
	DevicesMissing   int    `json:"devices_missing"`
	DevicesOverdue   int    `json:"devices_overdue"`
}

func ListPatches(ctx context.Context, pool *pgxpool.Pool) ([]PatchRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT coalesce(kb_or_advisory_id, ''), title, severity, has_kev,
		       devices_installed, devices_missing, devices_overdue
		FROM patch_compliance_by_patch
		ORDER BY devices_missing DESC, devices_overdue DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PatchRow
	for rows.Next() {
		var r PatchRow
		if err := rows.Scan(&r.KB, &r.Title, &r.Severity, &r.HasKEV, &r.DevicesInstalled, &r.DevicesMissing, &r.DevicesOverdue); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeviceRow is one row of device_patch_compliance_current, with the
// agent-reported device_id joined back in (the view itself only has the
// internal devices.id UUID).
type DeviceRow struct {
	DeviceID         string  `json:"device_id"` // agent_reported_id
	Hostname         string  `json:"hostname"`
	InstalledCount   int     `json:"installed_count"`
	MissingCount     int     `json:"missing_count"`
	MissingCritical  int     `json:"missing_critical"`
	MissingKEV       int     `json:"missing_kev"`
	OverdueCount     int     `json:"overdue_count"`
	CompliancePct    float64 `json:"compliance_pct"`
	ComplianceStatus string  `json:"compliance_status"`
}

func ListDevices(ctx context.Context, pool *pgxpool.Pool) ([]DeviceRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT coalesce(d.agent_reported_id, ''), c.hostname, c.installed_count, c.missing_count,
		       c.missing_critical, c.missing_kev, c.overdue_count, c.compliance_pct, c.compliance_status
		FROM device_patch_compliance_current c
		JOIN devices d ON d.id = c.device_id
		ORDER BY c.missing_count DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DeviceRow
	for rows.Next() {
		var r DeviceRow
		if err := rows.Scan(&r.DeviceID, &r.Hostname, &r.InstalledCount, &r.MissingCount,
			&r.MissingCritical, &r.MissingKEV, &r.OverdueCount, &r.CompliancePct, &r.ComplianceStatus); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Totals is the fleet-wide roll-up: how many patches installed vs. missing,
// summed across every device.
type Totals struct {
	Devices        int `json:"devices"`
	TotalInstalled int `json:"total_installed"`
	TotalMissing   int `json:"total_missing"`
}

func FleetTotals(ctx context.Context, pool *pgxpool.Pool) (Totals, error) {
	var t Totals
	err := pool.QueryRow(ctx, `
		SELECT count(*), coalesce(sum(installed_count), 0), coalesce(sum(missing_count), 0)
		FROM device_patch_compliance_current`).Scan(&t.Devices, &t.TotalInstalled, &t.TotalMissing)
	return t, err
}
