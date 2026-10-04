package ingest

import (
	"context"
	"fmt"
	"strings"

	agentcontrolv1 "aegis-one/gen/agentcontrol/v1"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5"
)

type PatchScanSummary struct {
	Matched         int // missing updates linked to a known patch_catalog row
	Unmatched       int // missing updates with no matching KB in patch_catalog yet
	MarkedInstalled int // previously-missing rows no longer reported missing
	SLAAssigned     int // open rows that got a policy + sla_due_at this scan
}

// PatchScan treats every received PatchScanResult as a full, successful snapshot
// of what's currently missing (the agent only ever builds and sends one after a
// scan that actually completed - a failed scan logs "status UNKNOWN" and sends
// nothing, per the agent's own internal/patch/scan_offline_windows.go). So:
//   - every Missing entry is upserted into device_patch_state as 'missing'
//     (matched by KB against patch_catalog) or into unmatched_patch_reports
//     (no catalog entry for that KB yet)
//   - every row that WAS missing/pending_reboot/failed for this device but is
//     NOT in this scan's Missing list is now treated as installed
//
// Limitation: a patch can also leave the missing list by becoming inapplicable
// (e.g. superseded) rather than actually being installed; this scan has no way to
// tell those apart from what the agent sends today, so it's recorded as
// 'installed' either way. Revisit if that distinction turns out to matter.
func (s *Store) PatchScan(ctx context.Context, known *identity.Known, psr *agentcontrolv1.PatchScanResult) (PatchScanSummary, error) {
	var summary PatchScanSummary

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return summary, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	matchedPatchIDs := make([]string, 0, len(psr.GetMissing()))

	for _, m := range psr.GetMissing() {
		patchID, found, err := resolvePatchID(ctx, tx, m.GetKbArticleIds())
		if err != nil {
			return summary, fmt.Errorf("resolve patch for update %s: %w", m.GetUpdateId(), err)
		}
		if !found {
			if err := recordUnmatched(ctx, tx, known.DeviceUUID, m); err != nil {
				return summary, fmt.Errorf("record unmatched update %s: %w", m.GetUpdateId(), err)
			}
			summary.Unmatched++
			continue
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO device_patch_state (device_id, patch_id, state, detection_source, first_detected_missing_at, last_evaluated_at)
			VALUES ($1, $2, 'missing', 'agent_wua', now(), now())
			ON CONFLICT (device_id, patch_id) DO UPDATE SET
				detection_source = 'agent_wua',
				last_evaluated_at = now(),
				-- A patch that was installed and is missing again (e.g. rolled back)
				-- starts a fresh SLA clock rather than inheriting the old one.
				first_detected_missing_at = CASE WHEN device_patch_state.state = 'installed' THEN now()
				                                 ELSE COALESCE(device_patch_state.first_detected_missing_at, now()) END,
				sla_due_at = CASE WHEN device_patch_state.state = 'installed' THEN NULL ELSE device_patch_state.sla_due_at END,
				policy_id  = CASE WHEN device_patch_state.state = 'installed' THEN NULL ELSE device_patch_state.policy_id END,
				state = 'missing'`,
			known.DeviceUUID, patchID,
		); err != nil {
			return summary, fmt.Errorf("upsert device_patch_state for patch %s: %w", patchID, err)
		}
		matchedPatchIDs = append(matchedPatchIDs, patchID)
		summary.Matched++
	}

	tag, err := tx.Exec(ctx, `
		UPDATE device_patch_state
		SET state = 'installed', installed_at = now(), last_evaluated_at = now()
		WHERE device_id = $1 AND state IN ('missing', 'pending_reboot', 'failed') AND NOT (patch_id = ANY($2))`,
		known.DeviceUUID, matchedPatchIDs,
	)
	if err != nil {
		return summary, fmt.Errorf("mark resolved device_patch_state rows: %w", err)
	}
	summary.MarkedInstalled = int(tag.RowsAffected())

	if summary.SLAAssigned, err = assignSLA(ctx, tx, known.DeviceUUID); err != nil {
		return summary, fmt.Errorf("assign SLA: %w", err)
	}

	// device_patch_compliance_current treats a stale last_patch_scan_at as
	// 'unknown' compliance (0005/0007) - without this, every device would show
	// unknown forever regardless of how recently it actually scanned.
	if _, err := tx.Exec(ctx, `UPDATE devices SET last_patch_scan_at = now() WHERE id = $1`, known.DeviceUUID); err != nil {
		return summary, fmt.Errorf("update last_patch_scan_at: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return summary, err
	}
	return summary, nil
}

// resolvePatchID tries every KB the agent reported for one missing update (a
// cumulative update can list more than one) against patch_catalog.
func resolvePatchID(ctx context.Context, tx pgx.Tx, kbArticleIDs []string) (patchID string, found bool, err error) {
	for _, kb := range kbArticleIDs {
		kb = normalizeKB(kb)
		if kb == "" {
			continue
		}
		var id string
		err := tx.QueryRow(ctx, `SELECT id FROM patch_catalog WHERE vendor = 'microsoft' AND kb_or_advisory_id = $1`, kb).Scan(&id)
		if err == nil {
			return id, true, nil
		}
		if err != pgx.ErrNoRows {
			return "", false, err
		}
	}
	return "", false, nil
}

func normalizeKB(kb string) string {
	kb = strings.ToUpper(strings.TrimSpace(kb))
	if kb == "" {
		return ""
	}
	if !strings.HasPrefix(kb, "KB") {
		kb = "KB" + kb
	}
	return kb
}

func recordUnmatched(ctx context.Context, tx pgx.Tx, deviceUUID string, m *agentcontrolv1.MissingUpdate) error {
	kb := ""
	if len(m.GetKbArticleIds()) > 0 {
		kb = normalizeKB(m.GetKbArticleIds()[0])
	}
	reportKey := "wua:" + m.GetUpdateId()
	_, err := tx.Exec(ctx, `
		INSERT INTO unmatched_patch_reports
			(device_id, report_key, detection_source, vendor_update_id, kb_or_advisory_id, title, reported_state)
		VALUES ($1, $2, 'agent_wua', $3, $4, $5, 'missing')
		ON CONFLICT (device_id, report_key) DO UPDATE SET
			report_count = unmatched_patch_reports.report_count + 1,
			last_reported_at = now(),
			title = EXCLUDED.title`,
		deviceUUID, reportKey, m.GetUpdateId(), nullIfEmpty(kb), m.GetTitle())
	return err
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
