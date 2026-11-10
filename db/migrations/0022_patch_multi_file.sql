-- =====================================================================================
-- 0022 multi-file patch push
--
-- A 24H2+ cumulative update ships its own .msu plus the checkpoint .msu file(s) it
-- builds on. The agent installs one file per install_patch, so the server pushes the
-- files one after another, checkpoints first (Microsoft's "install each MSU file
-- individually, in sequence"). A checkpoint the device already has comes back
-- NOT_APPLICABLE and the push moves on.
--
--   files         the install plan, in order: [{"kb", "name", "digest"}]
--   file_index    the file being worked on; file_digest follows it
--   file_results  one entry per finished file: kb, file, phase, reboot_required, reason
--
-- Rows created before this migration have files = '[]' and keep the one-file flow.
-- skipped_files is no longer written.
-- =====================================================================================

ALTER TABLE patch_deployment_results
    ADD COLUMN files        JSONB   NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN file_index   INTEGER NOT NULL DEFAULT 0 CHECK (file_index >= 0),
    ADD COLUMN file_results JSONB   NOT NULL DEFAULT '[]'::jsonb;
