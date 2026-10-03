-- 0008_patch_catalog_hash_optional.sql
-- patch_catalog.sha256_hash was NOT NULL from 0001, written back when a patch meant
-- "one file, one hash". 0005 introduced patch_files for the real one-to-many
-- (architecture/language) file list with its own per-file sha256_hash, making the
-- catalog-level hash redundant - and catalog metadata (CVE/KB/severity/title from a
-- feed like MSRC CVRF) is legitimately known before any file hash is. Relax it so
-- catalog ingestion isn't forced to fabricate a hash it doesn't have.
ALTER TABLE patch_catalog ALTER COLUMN sha256_hash DROP NOT NULL;

-- Needed so a feed sync (MSRC CVRF, run monthly) can upsert by (vendor, KB) instead of
-- inserting duplicate rows every run. NULL kb_or_advisory_id values stay unconstrained
-- (Postgres treats each NULL as distinct), which only matters for non-KB advisories we
-- don't ingest yet.
ALTER TABLE patch_catalog ADD CONSTRAINT uq_patch_catalog_vendor_kb UNIQUE (vendor, kb_or_advisory_id);
