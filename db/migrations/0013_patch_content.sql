-- 0013_patch_content.sql
-- Server-side patch content: where each Windows update's files come from, and
-- the local copies the server downloads on push and serves to agents over
-- FetchContent (kind "patch").
--
-- Source of the download URLs: the package.xml inside the current wsusscn2.cab
-- (scan_catalogs), which maps every update to its payload files (SHA-1 digest +
-- Microsoft download URL). No scraping of the Microsoft Update Catalog website.

-- When the cab's package.xml was last turned into wu_update_files.
ALTER TABLE scan_catalogs ADD COLUMN indexed_at TIMESTAMPTZ;

-- Installable payload files per update, from the current cab only (replaced
-- wholesale on each new index). update_id is the UpdateID a device reports in
-- its patch scan (MissingUpdate.update_id) - usually a bundle; the files of the
-- bundle's children are folded in under it.
CREATE TABLE wu_update_files (
    update_id       TEXT NOT NULL,      -- lowercase GUID
    file_digest     TEXT NOT NULL,      -- base64 SHA-1, as Microsoft publishes it
    file_name       TEXT NOT NULL,      -- e.g. windows11.0-kb5066835-x64_<sha1>.msu
    url             TEXT NOT NULL,
    PRIMARY KEY (update_id, file_digest)
);

-- Which update a device actually reported for a missing patch: the same KB has a
-- different UpdateID (and file) per OS version/architecture, so the push flow
-- needs the device's own one.
ALTER TABLE device_patch_state ADD COLUMN vendor_update_id TEXT;

-- One row per distinct file the server has been asked to fetch. Files are
-- identified by Microsoft's SHA-1 digest; after download the server also
-- records SHA-256, which is what agents verify.
CREATE TABLE patch_content (
    file_digest     TEXT PRIMARY KEY,
    file_name       TEXT NOT NULL,
    url             TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending', 'downloading', 'ready', 'failed')),
    sha256_hash     TEXT UNIQUE,
    size_bytes      BIGINT CHECK (size_bytes > 0),
    stored_name     TEXT,               -- relative to the server's content directory
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ready_at        TIMESTAMPTZ,
    CHECK (state <> 'ready' OR (sha256_hash IS NOT NULL AND size_bytes IS NOT NULL AND stored_name IS NOT NULL))
);
CREATE INDEX idx_patch_content_due ON patch_content(next_attempt_at) WHERE state = 'pending';

-- Push flow per device (patch_deployment_results row): download the file to the
-- server -> stage_patch (agent fetches it into its cache) -> install_patch.
-- Until the agent can take several files in one install, one file is sent:
-- the .msu of the pushed KB itself. Other installable files in the same update
-- (e.g. the 24H2 checkpoint .msu a cumulative update needs) are recorded in
-- skipped_files so the gap is visible.
ALTER TABLE patch_deployments ADD COLUMN created_by_api_client_id UUID REFERENCES api_clients(id);
ALTER TABLE patch_deployment_results
    ADD COLUMN step               TEXT CHECK (step IN ('downloading', 'staging', 'installing')),
    ADD COLUMN vendor_update_id   TEXT,
    ADD COLUMN file_digest        TEXT REFERENCES patch_content(file_digest),
    ADD COLUMN skipped_files      TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN stage_command_id   UUID REFERENCES agent_commands(id),
    ADD COLUMN install_command_id UUID REFERENCES agent_commands(id),
    ADD COLUMN updated_at         TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX idx_pdr_active ON patch_deployment_results(updated_at) WHERE status IN ('queued', 'in_progress');
-- One active push of the same patch to the same device at a time.
CREATE UNIQUE INDEX uq_pdr_active_device_patch ON patch_deployment_results(device_id, patch_id)
    WHERE status IN ('queued', 'in_progress');
