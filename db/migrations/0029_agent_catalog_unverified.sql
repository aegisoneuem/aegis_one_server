-- =====================================================================================
-- 0029 agent-reported catalog rows are unverified (security review 2026-11-19)
--
-- Any enrolled agent can add a patch_catalog row the MSRC feed doesn't know
-- (catalog_source 'agent_report', ingest/patchscan.go). Those rows are shared by
-- the whole fleet, so one compromised endpoint could plant a "critical" patch with
-- its own title and start SLA clocks on every device reporting that KB. From now on
-- the server writes such rows with severity 'unrated' (the agent's own rating stays
-- in vendor_severity); AssignSLA and the critical counters ignore 'unrated'.
--
-- This migration
--   1. re-rates the agent_report rows that already exist the same way, so the rule
--      holds for the existing catalog too (MSRC-sourced rows are untouched; when the
--      feed later carries one of these KBs it sets the real severity and 'msrc');
--   2. adds catalog_source to patch_compliance_by_patch so the console can badge
--      agent-reported patches as unverified (device_missing_patches already has it).
-- Run 0004 again afterwards (cmd/migrate does).
-- =====================================================================================

UPDATE patch_catalog
SET severity = 'unrated'
WHERE catalog_source = 'agent_report' AND severity <> 'unrated';

-- Same columns as 0005 plus catalog_source at the end (CREATE OR REPLACE VIEW may
-- only append columns).
CREATE OR REPLACE VIEW patch_compliance_by_patch AS
SELECT
    pc.id AS patch_id,
    pc.vendor,
    pc.kb_or_advisory_id,
    pc.title,
    pc.severity,
    pc.has_kev,
    count(*) FILTER (WHERE e.state IN ('missing', 'failed', 'pending_reboot') AND NOT e.is_excepted) AS devices_missing,
    count(*) FILTER (WHERE e.is_overdue AND NOT e.is_excepted)                                      AS devices_overdue,
    count(*) FILTER (WHERE e.state = 'installed')                                                   AS devices_installed,
    min(e.first_detected_missing_at) FILTER (WHERE e.state IN ('missing', 'failed', 'pending_reboot')) AS oldest_missing_since,
    pc.catalog_source
FROM patch_catalog pc
JOIN device_patch_state_effective e ON e.patch_id = pc.id
GROUP BY pc.id;
