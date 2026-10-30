-- 0014_agent_reported_patches.sql
-- The agent's scan report is the source of truth for what a device is missing.
-- A missing update whose KB isn't in the MSRC-fed catalog (non-security
-- updates, optional rollups, ...) now gets a catalog row built from the agent's
-- own report instead of only landing in unmatched_patch_reports, so it shows
-- up in the device's missing list and can be deployed.
--
-- catalog_source says where the row came from. When the MSRC feed later sees
-- the same KB it takes the row over (patchfeed upserts on (vendor, kb) and sets
-- 'msrc'), so there is never a second row for one KB.
ALTER TABLE patch_catalog ADD COLUMN catalog_source TEXT NOT NULL DEFAULT 'msrc'
    CHECK (catalog_source IN ('msrc', 'agent_report'));
