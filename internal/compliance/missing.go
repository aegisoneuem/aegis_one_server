package compliance

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MissingPatch is one patch the device's last scan reported missing (or whose
// install failed), and whether /internal/deploy can push it right now.
type MissingPatch struct {
	KB             string     `json:"kb"`
	Title          string     `json:"title"`
	Classification string     `json:"classification"`
	Severity       string     `json:"severity"`
	HasKEV         bool       `json:"has_kev"`
	State          string     `json:"state"` // missing | failed
	Source         string     `json:"catalog_source"`
	UpdateID       *string    `json:"update_id,omitempty"`
	MissingSince   *time.Time `json:"missing_since,omitempty"`
	SLADueAt       *time.Time `json:"sla_due_at,omitempty"`
	InstallTries   int        `json:"install_attempts"`
	LastError      *string    `json:"last_error,omitempty"`
	Deployable     bool       `json:"deployable"`
	NotDeployable  string     `json:"not_deployable_reason,omitempty"`
	ActiveDeployID *string    `json:"active_deployment_id,omitempty"`
}

// UnmatchedUpdate is a missing update the agent reported without a KB number
// (drivers and the like); it can't be cataloged or deployed.
type UnmatchedUpdate struct {
	UpdateID       *string   `json:"update_id,omitempty"`
	Title          *string   `json:"title,omitempty"`
	LastReportedAt time.Time `json:"last_reported_at"`
}

type DeviceMissing struct {
	DeviceID   string            `json:"device_id"`
	Hostname   string            `json:"hostname"`
	LastScanAt *time.Time        `json:"last_scan_at,omitempty"`
	Missing    []MissingPatch    `json:"missing"`
	Unmatched  []UnmatchedUpdate `json:"unmatched_without_kb"`
}

var ErrUnknownDevice = errors.New("unknown device")

// MissingForDevice lists what the device (agent-reported id) is missing per its
// latest scan.
func MissingForDevice(ctx context.Context, pool *pgxpool.Pool, deviceID string) (*DeviceMissing, error) {
	out := &DeviceMissing{DeviceID: deviceID, Missing: []MissingPatch{}, Unmatched: []UnmatchedUpdate{}}
	var deviceUUID string
	err := pool.QueryRow(ctx, `
		SELECT d.id, coalesce(d.hostname, ''),
		       (SELECT max(last_evaluated_at) FROM device_patch_state WHERE device_id = d.id)
		FROM devices d WHERE d.agent_reported_id = $1`, deviceID).Scan(&deviceUUID, &out.Hostname, &out.LastScanAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownDevice
	}
	if err != nil {
		return nil, err
	}

	// deployable mirrors patchdeploy.Create's checks: the scan gave an
	// UpdateID, the current scan cab has a file named for the KB, and no push
	// of it is already running.
	rows, err := pool.Query(ctx, `
		SELECT pc.kb_or_advisory_id, pc.title, pc.classification, pc.severity, pc.has_kev,
		       s.state, pc.catalog_source, s.vendor_update_id, s.first_detected_missing_at, s.sla_due_at,
		       s.install_attempts, s.last_error,
		       EXISTS (SELECT 1 FROM wu_update_files f
		               WHERE f.update_id = s.vendor_update_id
		                 AND position(lower(pc.kb_or_advisory_id) IN lower(f.file_name)) > 0) AS has_file,
		       (SELECT r.deployment_id::text FROM patch_deployment_results r
		        WHERE r.device_id = s.device_id AND r.patch_id = s.patch_id AND r.status IN ('queued', 'in_progress')
		        LIMIT 1) AS active_deployment
		FROM device_patch_state s
		JOIN patch_catalog pc ON pc.id = s.patch_id
		WHERE s.device_id = $1 AND s.state IN ('missing', 'failed')
		ORDER BY pc.has_kev DESC,
		         array_position(ARRAY['critical','high','medium','low','unrated'], pc.severity),
		         s.first_detected_missing_at`, deviceUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p MissingPatch
		var kb *string
		var hasFile bool
		if err := rows.Scan(&kb, &p.Title, &p.Classification, &p.Severity, &p.HasKEV, &p.State, &p.Source,
			&p.UpdateID, &p.MissingSince, &p.SLADueAt, &p.InstallTries, &p.LastError, &hasFile, &p.ActiveDeployID); err != nil {
			return nil, err
		}
		if kb != nil {
			p.KB = *kb
		}
		switch {
		case p.ActiveDeployID != nil:
			p.NotDeployable = "a deployment of this patch to this device is already running"
		case p.UpdateID == nil || *p.UpdateID == "":
			p.NotDeployable = "the scan did not report an UpdateID for it (rescan with a current agent)"
		case !hasFile:
			p.NotDeployable = "no download link for this update in the current scan cab"
		default:
			p.Deployable = true
		}
		out.Missing = append(out.Missing, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Ingest deletes the ones a later scan no longer reports.
	urows, err := pool.Query(ctx, `
		SELECT vendor_update_id, title, last_reported_at FROM unmatched_patch_reports
		WHERE device_id = $1 AND reported_state = 'missing' AND resolved_at IS NULL
		  AND kb_or_advisory_id IS NULL
		ORDER BY title`, deviceUUID)
	if err != nil {
		return nil, err
	}
	defer urows.Close()
	for urows.Next() {
		var u UnmatchedUpdate
		if err := urows.Scan(&u.UpdateID, &u.Title, &u.LastReportedAt); err != nil {
			return nil, err
		}
		out.Unmatched = append(out.Unmatched, u)
	}
	return out, urows.Err()
}
