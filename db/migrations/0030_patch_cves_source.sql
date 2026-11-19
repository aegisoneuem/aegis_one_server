-- =====================================================================================
-- 0030 patch->CVE links carry their source; only feed links drive has_kev
--      (security review 2026-11-19, tier 2 of the agent-reported catalog hardening)
--
-- An agent's scan report may name the CVEs an update fixes. 0029 stopped an
-- agent's severity claim from starting SLA clocks, but a CVE link it added still
-- counted for patch_catalog.has_kev: report any KB together with a CVE that is on
-- the CISA KEV list and kev.Apply flags the patch known-exploited for the whole
-- fleet - the tightest SLA there is, and the one case where an 'unrated' row gets
-- an SLA at all. From now on
--   * patch_cves.source says who asserted the link: 'msrc' (the vendor feed) or
--     'agent_report' (an endpoint);
--   * has_kev is derived from 'msrc' links only (kev.Apply); an agent link is kept
--     as information and is upgraded to 'msrc' when the feed confirms it.
--
-- This migration
--   1. adds the column; existing links default to 'msrc';
--   2. marks the links on agent-reported catalog rows 'agent_report' - the feed
--      sets catalog_source = 'msrc' whenever it links, so those can only have come
--      from agents. Links on rows the feed had already taken over are kept 'msrc':
--      an agent link planted before the takeover cannot be told apart here;
--   3. recomputes has_kev under the new rule (same statement as kev.Apply);
--   4. clears the SLA of open rows on an unrated, non-KEV patch. Such rows exist
--      from before 0029 (an agent's "Critical" was trusted) or from a planted KEV
--      link; under AssignSLA's rule they have no SLA, and leaving one makes the
--      device falsely overdue.
-- Run 0004 again afterwards (cmd/migrate does).
-- =====================================================================================

ALTER TABLE patch_cves
    ADD COLUMN source TEXT NOT NULL DEFAULT 'msrc'
        CHECK (source IN ('msrc', 'agent_report'));

UPDATE patch_cves pc
SET source = 'agent_report'
FROM patch_catalog p
WHERE p.id = pc.patch_id AND p.catalog_source = 'agent_report';

UPDATE patch_catalog p SET has_kev = sub.kev
FROM (
    SELECT p2.id, EXISTS (
        SELECT 1 FROM patch_cves pc JOIN cve_catalog c ON c.cve_id = pc.cve_id
        WHERE pc.patch_id = p2.id AND pc.source = 'msrc' AND c.is_kev) AS kev
    FROM patch_catalog p2
) sub
WHERE p.id = sub.id AND p.has_kev IS DISTINCT FROM sub.kev;

UPDATE device_patch_state s
SET sla_due_at = NULL, policy_id = NULL
FROM patch_catalog pc
WHERE pc.id = s.patch_id
  AND s.state IN ('missing', 'failed', 'pending_reboot')
  AND s.sla_due_at IS NOT NULL
  AND NOT pc.has_kev
  AND pc.severity = 'unrated';
