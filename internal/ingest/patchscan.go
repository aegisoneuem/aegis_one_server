package ingest

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5"
)

type PatchScanSummary struct {
	Matched            int // missing updates linked to a known patch_catalog row
	Unmatched          int // missing updates without a KB number (can't be cataloged)
	AgentCataloged     int // missing updates whose KB wasn't in the catalog; added from the report
	Superseded         int // missing updates the agent flagged as superseded
	InstalledReported  int // installed updates (agent's installed list) matched to the catalog
	MarkedInstalled    int // fallback only: previously-open rows assumed installed
	NoLongerApplicable int // previously-open rows in neither list (deleted)
	SLAAssigned        int // open rows that got a policy + sla_due_at this scan
	SupersedenceLinks  int // agent-reported supersedence added (agent_report KBs only)
}

// PatchScan applies a PatchScanResult as a full, successful snapshot (the agent
// only sends one after a scan that completed; a failed scan sends nothing).
// Since the server-side diff (internal/patchdiff) became the source of truth,
// this endpoint cab scan is optional (air-gapped / on-demand): it adds what the
// diff can't decide (standalone, .NET, non-security updates), and its cleanup
// below only touches its own 'agent_wua' rows, never the diff's.
//   - Missing, not superseded -> 'missing' (SLA clock per AssignSLA). A KB not
//     in the catalog gets a catalog row from the report itself
//     (catalog_source 'agent_report'); only updates with no well-formed KB at
//     all (e.g. drivers) go to unmatched_patch_reports.
//     Agent-created rows are UNVERIFIED (security review 2026-11-19): one
//     compromised endpoint writes them for the whole fleet, so they get
//     severity 'unrated' (no SLA, not counted as critical; the agent's own
//     rating is kept in vendor_severity), clipped text, and a KB article URL
//     only when it points at Microsoft. The MSRC feed takes the row over when
//     it carries the KB.
//   - Missing but superseded -> 'superseded': not counted as missing (its
//     superseding update is reported missing itself), never gets an SLA.
//   - Installed (the agent's authoritative WUA installed view) -> 'installed'.
//     Installed updates with no catalog match are skipped, not recorded as
//     unmatched: install history holds hundreds of old KBs outside our catalog.
//   - Rows that were open (missing/failed/pending_reboot/superseded) but are in
//     neither list:
//   - installed list present -> no longer applicable to this device -> deleted
//     (device_patch_state stores applicable patches only, 0005);
//   - installed list empty (agent/source that doesn't send it) -> fall back to
//     the old inference: assumed installed.
func (s *Store) PatchScan(ctx context.Context, known *identity.Known, psr *aegisonev1.PatchScanResult) (PatchScanSummary, error) {
	var summary PatchScanSummary

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return summary, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	seen := make([]string, 0, len(psr.GetMissing())+len(psr.GetInstalled()))
	unmatchedSeen := []string{} // report_keys of no-KB missing updates in this scan
	// UpdateID -> patch_catalog.id for this scan's updates, for supersedence.
	byUpdateID := map[string]string{}
	resolved := func(m *aegisonev1.MissingUpdate, patchID string) error {
		if id := deref(updateIDOf(m)); id != "" {
			byUpdateID[id] = patchID
		}
		if err := enrichAgentPatch(ctx, tx, patchID, m); err != nil {
			return fmt.Errorf("catalog metadata for update %s: %w", m.GetUpdateId(), err)
		}
		return nil
	}

	for _, m := range psr.GetMissing() {
		patchID, found, err := resolvePatchID(ctx, tx, m.GetKbArticleIds())
		if err != nil {
			return summary, fmt.Errorf("resolve patch for update %s: %w", m.GetUpdateId(), err)
		}
		if !found && firstKB(m) != "" {
			// A KB the MSRC feed doesn't know still becomes a catalog row (and
			// so a missing patch), marked agent_report / unrated: see above.
			if patchID, err = upsertAgentReportedPatch(ctx, tx, psr, m); err != nil {
				return summary, fmt.Errorf("catalog agent-reported update %s: %w", m.GetUpdateId(), err)
			}
			found = true
			summary.AgentCataloged++
		}
		if !found {
			if err := recordUnmatched(ctx, tx, known.DeviceUUID, m); err != nil {
				return summary, fmt.Errorf("record unmatched update %s: %w", m.GetUpdateId(), err)
			}
			unmatchedSeen = append(unmatchedSeen, "wua:"+m.GetUpdateId())
			summary.Unmatched++
			continue
		}
		seen = append(seen, patchID)
		if err := resolved(m, patchID); err != nil {
			return summary, err
		}

		if m.GetSuperseded() {
			if _, err := tx.Exec(ctx, `
				INSERT INTO device_patch_state (device_id, patch_id, state, detection_source, last_evaluated_at, vendor_update_id)
				VALUES ($1, $2, 'superseded', 'agent_wua', now(), $3)
				ON CONFLICT (device_id, patch_id) DO UPDATE SET
					state = 'superseded', detection_source = 'agent_wua', last_evaluated_at = now(),
					vendor_update_id = EXCLUDED.vendor_update_id`,
				known.DeviceUUID, patchID, updateIDOf(m)); err != nil {
				return summary, fmt.Errorf("upsert superseded patch %s: %w", patchID, err)
			}
			summary.Superseded++
			continue
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO device_patch_state (device_id, patch_id, state, detection_source, first_detected_missing_at, last_evaluated_at, vendor_update_id)
			VALUES ($1, $2, 'missing', 'agent_wua', now(), now(), $3)
			ON CONFLICT (device_id, patch_id) DO UPDATE SET
				detection_source = 'agent_wua',
				last_evaluated_at = now(),
				-- The device's own UpdateID for this KB: the push flow downloads
				-- that update's files (they differ per OS version/arch).
				vendor_update_id = EXCLUDED.vendor_update_id,
				-- A patch that was installed and is missing again (e.g. rolled back)
				-- starts a fresh SLA clock rather than inheriting the old one.
				first_detected_missing_at = CASE WHEN device_patch_state.state = 'installed' THEN now()
				                                 ELSE COALESCE(device_patch_state.first_detected_missing_at, now()) END,
				sla_due_at = CASE WHEN device_patch_state.state = 'installed' THEN NULL ELSE device_patch_state.sla_due_at END,
				policy_id  = CASE WHEN device_patch_state.state = 'installed' THEN NULL ELSE device_patch_state.policy_id END,
				state = 'missing'`,
			known.DeviceUUID, patchID, updateIDOf(m),
		); err != nil {
			return summary, fmt.Errorf("upsert device_patch_state for patch %s: %w", patchID, err)
		}
		summary.Matched++
	}

	for _, inst := range psr.GetInstalled() {
		patchID, found, err := resolvePatchID(ctx, tx, inst.GetKbArticleIds())
		if err != nil {
			return summary, fmt.Errorf("resolve installed update %s: %w", inst.GetUpdateId(), err)
		}
		if !found {
			continue
		}
		seen = append(seen, patchID)
		if err := resolved(inst, patchID); err != nil {
			return summary, err
		}
		// installed_at = when we first saw it installed (the agent doesn't send
		// the install date); kept across later scans.
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_patch_state (device_id, patch_id, state, detection_source, installed_at, last_evaluated_at)
			VALUES ($1, $2, 'installed', 'agent_wua', now(), now())
			ON CONFLICT (device_id, patch_id) DO UPDATE SET
				installed_at = CASE WHEN device_patch_state.state = 'installed' AND device_patch_state.installed_at IS NOT NULL
				                    THEN device_patch_state.installed_at ELSE now() END,
				state = 'installed', detection_source = 'agent_wua', last_evaluated_at = now()`,
			known.DeviceUUID, patchID); err != nil {
			return summary, fmt.Errorf("upsert installed patch %s: %w", patchID, err)
		}
		summary.InstalledReported++
	}

	if summary.SupersedenceLinks, err = linkAgentSupersedence(ctx, tx, byUpdateID, append(append([]*aegisonev1.MissingUpdate{}, psr.GetMissing()...), psr.GetInstalled()...)); err != nil {
		return summary, err
	}

	// The missing list is a full snapshot, so a no-KB update it no longer
	// carries is no longer missing on this device.
	if _, err := tx.Exec(ctx, `
		DELETE FROM unmatched_patch_reports
		WHERE device_id = $1 AND detection_source = 'agent_wua' AND reported_state = 'missing'
		  AND NOT (report_key = ANY($2))`, known.DeviceUUID, unmatchedSeen); err != nil {
		return summary, fmt.Errorf("remove stale unmatched reports: %w", err)
	}

	if len(psr.GetInstalled()) > 0 {
		tag, err := tx.Exec(ctx, `
			DELETE FROM device_patch_state
			WHERE device_id = $1 AND detection_source = 'agent_wua' AND state IN ('missing', 'pending_reboot', 'failed', 'superseded')
			  AND NOT (patch_id = ANY($2))`, known.DeviceUUID, seen)
		if err != nil {
			return summary, fmt.Errorf("remove no-longer-applicable rows: %w", err)
		}
		summary.NoLongerApplicable = int(tag.RowsAffected())
	} else {
		tag, err := tx.Exec(ctx, `
			UPDATE device_patch_state
			SET state = 'installed', installed_at = now(), last_evaluated_at = now()
			WHERE device_id = $1 AND detection_source = 'agent_wua' AND state IN ('missing', 'pending_reboot', 'failed')
			  AND NOT (patch_id = ANY($2))`,
			known.DeviceUUID, seen)
		if err != nil {
			return summary, fmt.Errorf("mark resolved device_patch_state rows: %w", err)
		}
		summary.MarkedInstalled = int(tag.RowsAffected())
	}

	if summary.SLAAssigned, err = AssignSLA(ctx, tx, known.DeviceUUID); err != nil {
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

// resolvePatchID tries every well-formed KB the agent reported for one missing
// update (a cumulative update can list more than one) against patch_catalog.
func resolvePatchID(ctx context.Context, tx pgx.Tx, kbArticleIDs []string) (patchID string, found bool, err error) {
	for _, kb := range kbArticleIDs {
		kb = NormalizeKB(kb)
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

// recordUnmatched keeps a missing update that could not be cataloged (no
// well-formed KB) so an operator can map it by hand.
func recordUnmatched(ctx context.Context, tx pgx.Tx, deviceUUID string, m *aegisonev1.MissingUpdate) error {
	kb := firstKB(m)
	reportKey := "wua:" + m.GetUpdateId()
	_, err := tx.Exec(ctx, `
		INSERT INTO unmatched_patch_reports
			(device_id, report_key, detection_source, vendor_update_id, kb_or_advisory_id, title, reported_state)
		VALUES ($1, $2, 'agent_wua', $3, $4, $5, 'missing')
		ON CONFLICT (device_id, report_key) DO UPDATE SET
			report_count = unmatched_patch_reports.report_count + 1,
			last_reported_at = now(),
			title = EXCLUDED.title`,
		deviceUUID, reportKey, clipN(m.GetUpdateId(), 255), nullIfEmpty(kb), clipN(m.GetTitle(), maxText))
	return err
}

// firstKB is the first well-formed KB (KBnnnnnnn) the agent listed for the
// update, "" when there is none.
func firstKB(m *aegisonev1.MissingUpdate) string {
	for _, kb := range m.GetKbArticleIds() {
		if k := NormalizeKB(kb); k != "" {
			return k
		}
	}
	return ""
}

// upsertAgentReportedPatch creates the catalog row for a KB only the agent
// knows about, from its WUA metadata, as an unverified row: severity is
// 'unrated' whatever the agent claims (the claim is kept in vendor_severity),
// so AssignSLA and the critical counters ignore it until the MSRC feed carries
// the KB and takes the row over (catalog_source 'msrc', real severity).
func upsertAgentReportedPatch(ctx context.Context, tx pgx.Tx, psr *aegisonev1.PatchScanResult, m *aegisonev1.MissingUpdate) (string, error) {
	product := psr.GetProductName()
	if len(m.GetProducts()) > 0 && m.GetProducts()[0] != "" {
		product = m.GetProducts()[0]
	}
	product = clipN(product, 255)
	if product == "" {
		product = "Windows"
	}
	title := clipN(m.GetTitle(), maxText)
	if title == "" {
		title = firstKB(m)
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO patch_catalog
			(vendor, product, kb_or_advisory_id, title, classification, severity, vendor_severity, os_family,
			 kb_article_url, catalog_source)
		VALUES ('microsoft', $1, $2, $3, $4, 'unrated', NULLIF($5, ''), 'windows', NULLIF($6, ''), 'agent_report')
		ON CONFLICT (vendor, kb_or_advisory_id) DO UPDATE SET kb_or_advisory_id = EXCLUDED.kb_or_advisory_id
		RETURNING id`,
		product, firstKB(m), title, classificationOf(m.GetClassification()),
		clipN(m.GetMsrcSeverity(), 64), agentArticleURL(m.GetSupportUrl())).Scan(&id)
	return id, err
}

// articleHosts are the only hosts an agent-supplied KB article link may point
// at: the link is shown to operators fleet-wide, and the agent is not trusted.
var articleHosts = map[string]bool{
	"support.microsoft.com":            true,
	"catalog.update.microsoft.com":     true,
	"www.catalog.update.microsoft.com": true,
	"learn.microsoft.com":              true,
	"msrc.microsoft.com":               true,
	"go.microsoft.com":                 true,
}

// agentArticleURL returns the agent's support URL when it is an https link to
// a Microsoft documentation host, "" otherwise.
func agentArticleURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 1024 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || !articleHosts[strings.ToLower(u.Hostname())] {
		return ""
	}
	for _, c := range raw {
		if c < 0x21 || c > 0x7e { // whitespace, control or non-ASCII: not a link we'd render
			return ""
		}
	}
	return raw
}

// classificationOf maps WUA's update classification names onto
// patch_catalog.classification.
func classificationOf(c string) string {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "security updates":
		return "security"
	case "critical updates":
		return "critical"
	case "update rollups":
		return "update_rollup"
	case "service packs":
		return "service_pack"
	case "feature packs":
		return "feature_pack"
	case "drivers":
		return "driver"
	case "definition updates":
		return "definition"
	case "updates", "":
		return "bugfix"
	}
	return "enhancement"
}

// updateIDOf is the reported Windows UpdateID, lowercased to match
// wu_update_files; NULL when the agent sent none.
func updateIDOf(m *aegisonev1.MissingUpdate) *string {
	return nullIfEmpty(strings.ToLower(strings.TrimSpace(m.GetUpdateId())))
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
