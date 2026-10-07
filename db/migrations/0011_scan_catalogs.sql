-- 0011_scan_catalogs.sql
-- Offline patch-scan catalogs the server redistributes to agents - today only
-- Microsoft's wsusscn2.cab, which the agent's offline scan
-- (internal/patch/scan_offline_windows.go) needs as a local file.
-- Not content_manifests: that table is per patch/software package and requires
-- an Ed25519 manifest signature (manifest-signing key + agent-side verification
-- don't exist yet). Integrity here is SHA-256 over an authenticated channel.
-- One file per distinct sha256; exactly one current row per source.
CREATE TABLE scan_catalogs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source                  TEXT NOT NULL CHECK (source IN ('microsoft_wsusscn2')),
    sha256_hash             TEXT NOT NULL UNIQUE,
    size_bytes              BIGINT NOT NULL CHECK (size_bytes > 0),
    file_name               TEXT NOT NULL,          -- relative to the server's content directory
    source_url              TEXT NOT NULL,
    source_etag             TEXT,
    source_last_modified    TIMESTAMPTZ,
    downloaded_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_current              BOOLEAN NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX uq_scan_catalogs_one_current ON scan_catalogs(source) WHERE is_current;
