-- =====================================================================================
-- AEGIS ONE - Database Schema v4
-- File 7: 0007_ingestion_support.sql
-- Runs on plain PostgreSQL 14+, AFTER 0001-0006 (0006 optional). Additive only.
-- Re-run 0004_db_roles.sql afterwards so new tables get the same grants.
--
-- These are the tables the agent-ingestion server code needs before it is written:
--   system_settings ......... tunables in the DB, not hard-coded (scan freshness, intervals)
--   agent_config_profiles ... per-site / per-group agent settings (check-in interval,
--                             bandwidth limit, modules) - ADR: "configurable per site"
--   agent_stream_offsets .... dedup: agents buffer offline and RESEND on reconnect;
--                             each stream carries a sequence number, old ones are skipped
--   devices.inventory_state_hash  delta inventory safety: hash mismatch => ask agent for full resync
--   content_feeds / feed_sync_runs  where patch/CVE/KEV/EPSS data comes from, incl. OFFLINE
--                             bundles for air-gapped sites
--   unmatched_patch_reports . agent reports an update not in our catalog - keep it, don't drop it
--   agent_releases .......... signed agent builds for self-update + anti-downgrade
--   alerts .................. one place for problems, with dedup so 10k devices != 10k alerts
-- =====================================================================================


-- -------------------------------------------------------------------------------------
-- 1. SYSTEM SETTINGS  (no secrets here - those stay in Vault)
-- -------------------------------------------------------------------------------------

CREATE TABLE system_settings (
    key                 TEXT PRIMARY KEY,
    value               JSONB NOT NULL,
    description         TEXT,
    updated_by_user_id  UUID REFERENCES users(id),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_settings (key, value, description) VALUES
    ('compliance.scan_freshness_days',      '7',     'Device compliance shows as unknown if the last patch scan is older than this'),
    ('ingest.full_inventory_resync_hours',  '24',    'Force a full (non-delta) inventory at least this often'),
    ('agent.offline_after_minutes',         '15',    'No heartbeat for this long => agent counted as offline')
ON CONFLICT (key) DO NOTHING;

CREATE OR REPLACE FUNCTION setting_int(p_key TEXT, p_default INTEGER) RETURNS INTEGER
LANGUAGE sql STABLE AS $$
    SELECT coalesce((SELECT (value #>> '{}')::integer FROM system_settings WHERE key = p_key), p_default)
$$;

-- Same view as 0005, but the 7-day freshness window now comes from system_settings.
CREATE OR REPLACE VIEW device_patch_compliance_current AS
SELECT
    d.id AS device_id,
    d.hostname,
    d.os_family,
    d.device_class,
    d.criticality,
    d.primary_group_id,
    d.last_patch_scan_at,
    count(e.patch_id) FILTER (WHERE e.state = 'installed')                                           AS installed_count,
    count(e.patch_id) FILTER (WHERE e.state IN ('missing', 'failed', 'pending_reboot') AND NOT e.is_excepted) AS missing_count,
    count(e.patch_id) FILTER (WHERE e.state IN ('missing', 'failed', 'pending_reboot') AND NOT e.is_excepted
                                AND e.severity = 'critical')                                          AS missing_critical,
    count(e.patch_id) FILTER (WHERE e.state IN ('missing', 'failed', 'pending_reboot') AND NOT e.is_excepted
                                AND e.has_kev)                                                        AS missing_kev,
    count(e.patch_id) FILTER (WHERE e.is_overdue AND NOT e.is_excepted)                               AS overdue_count,
    count(e.patch_id) FILTER (WHERE e.state = 'pending_reboot')                                       AS pending_reboot_count,
    count(e.patch_id) FILTER (WHERE e.is_excepted AND e.state <> 'installed')                         AS excepted_count,
    CASE
        WHEN count(e.patch_id) FILTER (WHERE e.state = 'installed' OR (e.state IN ('missing', 'failed', 'pending_reboot') AND NOT e.is_excepted)) = 0
            THEN 100.00
        ELSE round(100.0 * count(e.patch_id) FILTER (WHERE e.state = 'installed')
                   / count(e.patch_id) FILTER (WHERE e.state = 'installed'
                                               OR (e.state IN ('missing', 'failed', 'pending_reboot') AND NOT e.is_excepted)), 2)
    END AS compliance_pct,
    CASE
        WHEN d.last_patch_scan_at IS NULL
          OR d.last_patch_scan_at < now() - make_interval(days => setting_int('compliance.scan_freshness_days', 7))
            THEN 'unknown'
        WHEN count(e.patch_id) FILTER (WHERE e.is_overdue AND NOT e.is_excepted) > 0 THEN 'non_compliant'
        ELSE 'compliant'
    END AS compliance_status
FROM devices d
LEFT JOIN device_patch_state_effective e ON e.device_id = d.id
WHERE d.status = 'active'
GROUP BY d.id;


-- -------------------------------------------------------------------------------------
-- 2. AGENT CONFIG PROFILES
-- -------------------------------------------------------------------------------------
-- Resolution: group profile > site profile > default (lowest priority number wins within a
-- level). Changes reach agents as a SIGNED command over the existing stream (agent_commands),
-- so a tampered config cannot disable modules silently.

CREATE TABLE agent_config_profiles (
    id                              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                            TEXT NOT NULL UNIQUE,
    target_site_id                  UUID REFERENCES sites(id) ON DELETE CASCADE,
    target_group_id                 UUID REFERENCES device_groups(id) ON DELETE CASCADE,
    is_default                      BOOLEAN NOT NULL DEFAULT false,
    priority                        INTEGER NOT NULL DEFAULT 100,
    heartbeat_interval_seconds      INTEGER NOT NULL DEFAULT 60     CHECK (heartbeat_interval_seconds BETWEEN 15 AND 3600),
    inventory_interval_seconds      INTEGER NOT NULL DEFAULT 86400  CHECK (inventory_interval_seconds >= 900),
    patch_scan_interval_seconds     INTEGER NOT NULL DEFAULT 43200  CHECK (patch_scan_interval_seconds >= 900),
    dex_sample_interval_seconds     INTEGER NOT NULL DEFAULT 300    CHECK (dex_sample_interval_seconds >= 60),
    bandwidth_limit_kbps            INTEGER CHECK (bandwidth_limit_kbps > 0),   -- NULL = no limit
    peer_cache_allowed              BOOLEAN NOT NULL DEFAULT true,
    modules_enabled                 TEXT[] NOT NULL DEFAULT '{patch,software,inventory,va,dex}',
    log_level                       TEXT NOT NULL DEFAULT 'info' CHECK (log_level IN ('debug', 'info', 'warn', 'error')),
    config_version                  INTEGER NOT NULL DEFAULT 1,     -- bump on every change
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(target_site_id, target_group_id) <= 1),
    CHECK (NOT is_default OR (target_site_id IS NULL AND target_group_id IS NULL))
);
CREATE UNIQUE INDEX uq_agent_config_one_default ON agent_config_profiles(is_default) WHERE is_default;
CREATE TRIGGER trg_agent_config_updated_at BEFORE UPDATE ON agent_config_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

INSERT INTO agent_config_profiles (name, is_default) VALUES ('Default', true)
ON CONFLICT (name) DO NOTHING;

ALTER TABLE agents
    ADD COLUMN applied_config_profile_id UUID REFERENCES agent_config_profiles(id),
    ADD COLUMN applied_config_version    INTEGER;   -- lets the server see who is on stale config


-- -------------------------------------------------------------------------------------
-- 3. INGESTION DEDUP & DELTA SAFETY
-- -------------------------------------------------------------------------------------
-- Every non-heartbeat message from an agent carries (stream, sequence). Ingest pattern:
--   UPDATE agent_stream_offsets SET last_sequence = $seq, last_received_at = now()
--    WHERE agent_id = $agent AND stream = $stream AND last_sequence < $seq;
--   -> 0 rows updated  = duplicate or out-of-order resend: acknowledge it, don't apply it.
--   (First message per stream: INSERT ... ON CONFLICT DO NOTHING, then the UPDATE.)
-- Sequences must be monotonic per agent per stream and survive agent restarts (they live
-- in the agent's encrypted local buffer).

CREATE TABLE agent_stream_offsets (
    agent_id            UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    stream              TEXT NOT NULL CHECK (stream IN ('inventory', 'software_inventory', 'patch_scan',
                                                        'vuln_scan', 'dex', 'command_result')),
    last_sequence       BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_received_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, stream)
);

ALTER TABLE devices
    ADD COLUMN inventory_state_hash TEXT;   -- agent sends a hash of its full inventory; mismatch => request full resync


-- -------------------------------------------------------------------------------------
-- 4. CONTENT FEEDS  (patch metadata, CVE, KEV, EPSS, third-party catalog)
-- -------------------------------------------------------------------------------------
-- source_mode 'offline_bundle' is the air-gapped path: an operator imports a signed bundle
-- file; the bundle's hash and signature are verified before anything is ingested (fail-closed).

CREATE TABLE content_feeds (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL UNIQUE,      -- e.g. 'microsoft_updates', 'nvd_cve', 'cisa_kev'
    feed_type           TEXT NOT NULL CHECK (feed_type IN ('patch_metadata', 'cve', 'kev', 'epss', 'third_party_apps')),
    source_mode         TEXT NOT NULL DEFAULT 'online' CHECK (source_mode IN ('online', 'offline_bundle')),
    source_url          TEXT,
    sync_interval_hours INTEGER NOT NULL DEFAULT 24 CHECK (sync_interval_hours > 0),
    is_enabled          BOOLEAN NOT NULL DEFAULT true,
    sync_cursor         TEXT,                      -- etag / last-modified / page token for incremental sync
    last_success_at     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE feed_sync_runs (
    id                          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    feed_id                     UUID NOT NULL REFERENCES content_feeds(id) ON DELETE CASCADE,
    status                      TEXT NOT NULL DEFAULT 'running'
                                    CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
    items_added                 INTEGER NOT NULL DEFAULT 0,
    items_updated               INTEGER NOT NULL DEFAULT 0,
    items_rejected              INTEGER NOT NULL DEFAULT 0,   -- hash/signature mismatch => rejected, never ingested
    bundle_sha256               TEXT,                          -- offline bundles only
    bundle_signature_verified   BOOLEAN,
    initiated_by_user_id        UUID REFERENCES users(id),     -- NULL = scheduled
    started_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at                TIMESTAMPTZ,
    error_message               TEXT
);
CREATE INDEX idx_feed_sync_runs_feed ON feed_sync_runs(feed_id, started_at DESC);


-- -------------------------------------------------------------------------------------
-- 5. UNMATCHED PATCH REPORTS
-- -------------------------------------------------------------------------------------
-- Scan says "update X is missing/installed" but X isn't in patch_catalog yet (catalog lag,
-- vendor out-of-band release). Kept here, then linked once the catalog catches up.

CREATE TABLE unmatched_patch_reports (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    report_key          TEXT NOT NULL,          -- app-built, e.g. 'wua:<UpdateID>' or 'pkg:openssl=3.0.2-0ubuntu1.18'
    detection_source    TEXT NOT NULL CHECK (detection_source IN ('agent_wua', 'agent_package_manager', 'agent_rule', 'agentless_scan')),
    vendor_update_id    TEXT,
    kb_or_advisory_id   TEXT,
    package_name        TEXT,
    package_version     TEXT,
    title               TEXT,
    reported_state      TEXT CHECK (reported_state IN ('missing', 'installed', 'pending_reboot', 'failed')),
    report_count        INTEGER NOT NULL DEFAULT 1,
    first_reported_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_reported_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_patch_id   UUID REFERENCES patch_catalog(id),
    resolved_at         TIMESTAMPTZ,
    UNIQUE (device_id, report_key)
);
CREATE INDEX idx_unmatched_open ON unmatched_patch_reports(report_key) WHERE resolved_patch_id IS NULL;


-- -------------------------------------------------------------------------------------
-- 6. AGENT RELEASES  (Agent Spec: signed, staged self-update + anti-downgrade)
-- -------------------------------------------------------------------------------------

ALTER TABLE signing_keys
    DROP CONSTRAINT signing_keys_key_purpose_check,
    ADD CONSTRAINT signing_keys_key_purpose_check
        CHECK (key_purpose IN ('command_signing', 'manifest_signing', 'agent_release_signing'));

CREATE TABLE agent_releases (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version             TEXT NOT NULL,                 -- '1.4.2'
    version_sort        INTEGER[] NOT NULL,            -- {1,4,2}: numeric compare for "is this older?"
    os_family           TEXT NOT NULL CHECK (os_family IN ('windows', 'linux', 'macos')),
    architecture        TEXT NOT NULL CHECK (architecture IN ('x86', 'x64', 'arm64')),
    channel             TEXT NOT NULL DEFAULT 'pilot' CHECK (channel IN ('pilot', 'stable')),
    file_name           TEXT NOT NULL,
    size_bytes          BIGINT,
    sha256_hash         TEXT NOT NULL,
    signature_ed25519   TEXT NOT NULL,
    signing_key_id      UUID NOT NULL REFERENCES signing_keys(id),
    is_revoked          BOOLEAN NOT NULL DEFAULT false, -- pulled release: never offered again
    revoked_reason      TEXT,
    released_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (version, os_family, architecture)
);
CREATE INDEX idx_agent_releases_pick ON agent_releases(os_family, architecture, channel, version_sort DESC)
    WHERE NOT is_revoked;


-- -------------------------------------------------------------------------------------
-- 7. ALERTS
-- -------------------------------------------------------------------------------------
-- dedup_key groups repeats: the same problem bumps occurrence_count instead of creating
-- thousands of rows (e.g. 'feed_sync_failed:nvd_cve', 'agent_offline:<agent_id>').

CREATE TABLE alerts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_type              TEXT NOT NULL,   -- 'content_integrity_failure', 'agent_offline', 'deployment_auto_paused',
                                             -- 'kev_detected', 'revoked_cert_connect_attempt', 'feed_sync_failed'
    severity                TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    device_id               UUID REFERENCES devices(id) ON DELETE CASCADE,
    related_type            TEXT,
    related_id              UUID,
    title                   TEXT NOT NULL,
    details                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    status                  TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    dedup_key               TEXT,
    occurrence_count        INTEGER NOT NULL DEFAULT 1,
    first_seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_by_user_id UUID REFERENCES users(id),
    acknowledged_at         TIMESTAMPTZ,
    resolved_at             TIMESTAMPTZ
);
-- only one OPEN alert per dedup_key; once resolved, a new occurrence opens a fresh alert
CREATE UNIQUE INDEX uq_alerts_open_dedup ON alerts(dedup_key) WHERE status <> 'resolved' AND dedup_key IS NOT NULL;
CREATE INDEX idx_alerts_status ON alerts(status, severity, last_seen_at DESC);
CREATE INDEX idx_alerts_device ON alerts(device_id);
