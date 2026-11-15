package ingest

// Patch operations reports that were only logged until 0027: the agent's cab
// scan runs (ActionStatus "scan-<unix>"), "patch cache full", and the cab
// scan's update metadata (CVEs, size, description, supersedence).

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5"
)

const (
	// scanRunRetention is how long device_patch_scan_runs rows are kept.
	scanRunRetention = 90 * 24 * time.Hour
	// maxPendingRebootKBs caps DeviceStateReport.reboot_pending_kbs.
	maxPendingRebootKBs = 200
	// maxAgentCVEs / maxAgentSupersedes cap what one reported update may link.
	maxAgentCVEs       = 100
	maxAgentSupersedes = 100
)

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

// ScanRunStatus maps an ActionStatus phase onto device_patch_scan_runs.status.
func ScanRunStatus(p aegisonev1.ActionPhase) string {
	switch p {
	case aegisonev1.ActionPhase_ACTION_PHASE_SUCCESS:
		return "succeeded"
	case aegisonev1.ActionPhase_ACTION_PHASE_FAILED:
		return "failed"
	default:
		return "running"
	}
}

// IsScanRun reports whether st is the agent's own cab scan status (not a
// command we issued): action_type "scan", action_id like "scan-1761130000".
func IsScanRun(st *aegisonev1.ActionStatus) bool {
	id := st.GetActionId()
	return st.GetActionType() == "scan" && id != "" && len(id) <= 64 && strings.HasPrefix(id, "scan-")
}

// ScanRun records one cab scan status. A finished scan (succeeded or failed)
// also sets devices.last_cab_scan_*; an older run arriving late (the agent
// buffers while offline) never overwrites a newer one.
func (s *Store) ScanRun(ctx context.Context, known *identity.Known, st *aegisonev1.ActionStatus) error {
	now := time.Now()
	status := ScanRunStatus(st.GetPhase())
	started, finished := optTime(st.GetStartedAt(), now), optTime(st.GetFinishedAt(), now)
	reason := nullableN(st.GetReason(), 1000)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_patch_scan_runs (device_id, action_id, status, reason, started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (device_id, action_id) DO UPDATE SET
			status = EXCLUDED.status, reason = COALESCE(EXCLUDED.reason, device_patch_scan_runs.reason),
			started_at = COALESCE(EXCLUDED.started_at, device_patch_scan_runs.started_at),
			finished_at = COALESCE(EXCLUDED.finished_at, device_patch_scan_runs.finished_at), received_at = now()
		WHERE device_patch_scan_runs.status = 'running'`,
		known.DeviceUUID, st.GetActionId(), status, reason, started, finished); err != nil {
		return fmt.Errorf("upsert scan run: %w", err)
	}
	if status != "running" {
		at := now
		if finished != nil {
			at = *finished
		}
		if _, err := tx.Exec(ctx, `
			UPDATE devices SET last_cab_scan_at = $2, last_cab_scan_status = $3, last_cab_scan_reason = $4
			WHERE id = $1 AND (last_cab_scan_at IS NULL OR last_cab_scan_at <= $2)`,
			known.DeviceUUID, at, status, reason); err != nil {
			return fmt.Errorf("update last cab scan: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM device_patch_scan_runs WHERE device_id = $1 AND received_at < $2`,
		known.DeviceUUID, now.Add(-scanRunRetention)); err != nil {
		return fmt.Errorf("prune scan runs: %w", err)
	}
	return tx.Commit(ctx)
}

// optTime is a reported unix time, or nil when unset or implausible.
func optTime(sec int64, now time.Time) *time.Time {
	if sec <= 0 {
		return nil
	}
	t := time.Unix(sec, 0)
	if t.Before(now.Add(-35*24*time.Hour)) || t.After(now.Add(10*time.Minute)) {
		return nil
	}
	return &t
}

// CacheFullAlertKey is the alerts.dedup_key of a device's open "patch cache
// full" alert.
func CacheFullAlertKey(deviceUUID string) string { return "patch_cache_full:" + deviceUUID }

// CacheFull records the agent's CacheFullReport on the device and opens (or
// bumps) a medium alert: patches can't be staged until the cache cap is raised
// or the cache is cleaned up.
func (s *Store) CacheFull(ctx context.Context, known *identity.Known, cf *aegisonev1.CacheFullReport) error {
	nonNeg := func(v int64) *int64 {
		if v < 0 {
			return nil
		}
		return &v
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET patch_cache_full_at = now(), patch_cache_needed_bytes = $2,
		    patch_cache_cap_bytes = $3, patch_cache_in_use_bytes = $4
		WHERE id = $1`, known.DeviceUUID, nonNeg(cf.GetNeededBytes()), nonNeg(cf.GetCapBytes()), nonNeg(cf.GetInUseBytes())); err != nil {
		return fmt.Errorf("update patch cache: %w", err)
	}
	details, _ := json.Marshal(map[string]any{
		"needed_bytes": cf.GetNeededBytes(), "cap_bytes": cf.GetCapBytes(), "in_use_bytes": cf.GetInUseBytes(),
		"pending_id": clipN(cf.GetPendingId(), 200), "message": clipN(cf.GetMessage(), 500),
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO alerts (alert_type, severity, device_id, title, details, dedup_key)
		VALUES ('patch_cache_full', 'medium', $1, $2, $3::jsonb, $4)
		ON CONFLICT (dedup_key) WHERE status <> 'resolved' AND dedup_key IS NOT NULL
		DO UPDATE SET occurrence_count = alerts.occurrence_count + 1, last_seen_at = now(), details = EXCLUDED.details`,
		known.DeviceUUID, fmt.Sprintf("Patch cache full on %s: patches can't be staged", known.DeviceID),
		string(details), CacheFullAlertKey(known.DeviceUUID)); err != nil {
		return fmt.Errorf("raise cache-full alert: %w", err)
	}
	return tx.Commit(ctx)
}

// CacheRecovered clears the device's cache-full state and resolves its alert
// once the agent stages a patch again. Returns whether an alert was resolved.
func (s *Store) CacheRecovered(ctx context.Context, known *identity.Known) (bool, error) {
	if _, err := s.pool.Exec(ctx, `UPDATE devices SET patch_cache_full_at = NULL WHERE id = $1 AND patch_cache_full_at IS NOT NULL`,
		known.DeviceUUID); err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE alerts SET status = 'resolved', resolved_at = now(),
		    details = details || jsonb_build_object('resolved_by', 'patch staged again')
		WHERE dedup_key = $1 AND status <> 'resolved'`, CacheFullAlertKey(known.DeviceUUID))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// pendingRebootKBs normalizes DeviceStateReport.reboot_pending_kbs.
func pendingRebootKBs(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, k := range in {
		if kb := NormalizeKB(k); kb != "" && !seen[kb] && len(out) < maxPendingRebootKBs {
			seen[kb] = true
			out = append(out, kb)
		}
	}
	return out
}

// markPendingReboot moves the device's still-open rows for KBs waiting on a
// reboot to 'pending_reboot': installed, not effective until the restart.
func markPendingReboot(ctx context.Context, tx pgx.Tx, deviceUUID string, kbs []string) error {
	if len(kbs) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `
		UPDATE device_patch_state s SET state = 'pending_reboot', last_evaluated_at = now()
		FROM patch_catalog p
		WHERE s.device_id = $1 AND s.patch_id = p.id AND s.state IN ('missing', 'failed')
		  AND p.vendor = 'microsoft' AND p.kb_or_advisory_id = ANY($2)`, deviceUUID, kbs)
	return err
}

// enrichAgentPatch fills catalog fields from the cab scan's metadata - only
// for KBs that came from agent reports (catalog_source 'agent_report'): the
// MSRC feed stays the authority for everything it knows, and one endpoint
// can't rewrite fleet-wide catalog rows.
func enrichAgentPatch(ctx context.Context, tx pgx.Tx, patchID string, m *aegisonev1.MissingUpdate) error {
	var size *float64
	if v := m.GetSizeMb(); v > 0 && v < 1e9 {
		size = &v
	}
	var rev *int32
	if v := m.GetRevisionNumber(); v > 0 {
		rev = &v
	}
	tag, err := tx.Exec(ctx, `
		UPDATE patch_catalog SET
		    description      = COALESCE($2, description),
		    download_size_mb = COALESCE($3, download_size_mb),
		    reboot_behavior  = CASE WHEN $4 THEN CASE WHEN reboot_behavior = 'always' THEN 'always' ELSE 'may' END ELSE 'never' END,
		    revision         = GREATEST(revision, COALESCE($5, revision)),
		    vendor_update_id = COALESCE(vendor_update_id, $6)
		WHERE id = $1 AND catalog_source = 'agent_report'`,
		patchID, nullableN(m.GetDescription(), 4000), size, m.GetRebootRequired(), rev, updateIDOf(m))
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	cves := agentCVEs(m.GetCveIds())
	if len(cves) == 0 {
		return nil
	}
	// The CVE may be new to us: a bare cve_catalog row (severity unrated);
	// the feeds fill in the rest when they carry it.
	if _, err := tx.Exec(ctx, `INSERT INTO cve_catalog (cve_id) SELECT unnest($1::text[]) ON CONFLICT DO NOTHING`, cves); err != nil {
		return fmt.Errorf("add reported CVEs: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO patch_cves (patch_id, cve_id) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING`,
		patchID, cves); err != nil {
		return fmt.Errorf("link reported CVEs: %w", err)
	}
	return nil
}

// agentCVEs keeps well-formed CVE ids, upper-cased, de-duplicated and capped.
func agentCVEs(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if cveRe.MatchString(c) && !seen[c] && len(out) < maxAgentCVEs {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// linkAgentSupersedence records "m supersedes these updates" from the scan,
// for updates of the same scan that resolved to catalog rows - again only
// between agent-reported KBs, never touching the MSRC chain.
func linkAgentSupersedence(ctx context.Context, tx pgx.Tx, byUpdateID map[string]string, updates []*aegisonev1.MissingUpdate) (int, error) {
	n := 0
	for _, m := range updates {
		superseding := byUpdateID[deref(updateIDOf(m))]
		if superseding == "" {
			continue
		}
		for i, old := range m.GetSupersededUpdateIds() {
			if i >= maxAgentSupersedes {
				break
			}
			superseded := byUpdateID[strings.ToLower(strings.TrimSpace(old))]
			if superseded == "" || superseded == superseding {
				continue
			}
			tag, err := tx.Exec(ctx, `
				INSERT INTO patch_supersedence (superseding_patch_id, superseded_patch_id)
				SELECT $1, $2 WHERE (SELECT count(*) FROM patch_catalog WHERE id IN ($1, $2) AND catalog_source = 'agent_report') = 2
				ON CONFLICT DO NOTHING`, superseding, superseded)
			if err != nil {
				return n, fmt.Errorf("link supersedence: %w", err)
			}
			n += int(tag.RowsAffected())
		}
	}
	return n, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
