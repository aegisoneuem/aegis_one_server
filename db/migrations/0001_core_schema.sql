-- =====================================================================================
-- AEGIS ONE - Application Server Database Schema - v2
-- File 1 of 4: 0001_core_schema.sql
-- Runs on plain PostgreSQL 14+ (no TimescaleDB needed for this file).
--
-- Changes from v1 (0001_init_schema.sql):
--   * Security Design Review v3 items are now modelled:
--       - signing_keys ............ Ed25519 key rotation with a 30-day dual-key overlap
--       - agent_certificates ...... per-agent cert history (short-lived, auto-rotated certs)
--                                   + revocation checked by the server at every reconnect
--       - agent_commands .......... signed commands, idempotency key, Run-As auto-audited
--       - agent_local_acl_policies  LAAC - signed local-access ACL pushed to agents
--       - licenses ................ signed license file cache (trust = embedded public key)
--       - api_clients/api_tokens .. Platform API: scoped tokens, same RBAC, per-client rate limit
--       - backup_runs ............. encrypted-backup records for the backup_operator role
--   * audit_log hardened: blocks UPDATE, DELETE and TRUNCATE; records actor type and
--     source (application / OS auth / Postgres) so server-admin actions share one pipeline.
--   * TimescaleDB parts moved to 0002_timescale.sql so this file also runs on plain Postgres.
--   * updated_at kept current by trigger.
--
-- Assumption (unchanged): single-tenant - one database per Aegis One appliance.
-- =====================================================================================

-- No extensions needed here: gen_random_uuid() is built into PostgreSQL 13+.

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- -------------------------------------------------------------------------------------
-- 1. RBAC, USERS, PLATFORM API CLIENTS & AUDIT LOG
-- -------------------------------------------------------------------------------------

CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,               -- seeded in 0003_seed_roles.sql
    permissions     JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_system_role  BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username            TEXT NOT NULL UNIQUE,
    email               TEXT NOT NULL UNIQUE,
    password_hash       TEXT,                    -- Argon2id; NULL for SSO-only accounts
    mfa_totp_secret_enc BYTEA,                   -- AES-256-GCM encrypted by the app, never plaintext
    sso_subject         TEXT,
    role_id             UUID NOT NULL REFERENCES roles(id),
    status              TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'disabled', 'locked')),
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Users are disabled, not deleted: audit_log references them, so a delete is blocked by FK.
CREATE INDEX idx_users_role_id ON users(role_id);
CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Platform API (Security Review: scoped tokens, same RBAC as console, per-key rate limit)
CREATE TABLE api_clients (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    TEXT NOT NULL UNIQUE,
    role_id                 UUID NOT NULL REFERENCES roles(id),
    rate_limit_per_minute   INTEGER NOT NULL DEFAULT 600 CHECK (rate_limit_per_minute > 0),
    created_by_user_id      UUID REFERENCES users(id),
    disabled_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_client_id   UUID NOT NULL REFERENCES api_clients(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,          -- hash only; the raw token is shown once, never stored
    scopes          TEXT[] NOT NULL DEFAULT '{}',   -- e.g. {devices:read,patch:deploy}
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_tokens_client ON api_tokens(api_client_id);

-- Append-only audit log. One destination for app events, OS auth logs and Postgres
-- privileged-role logs (Security Review: "one destination, not a second silo").
CREATE TABLE audit_log (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source              TEXT NOT NULL DEFAULT 'application'
                            CHECK (source IN ('application', 'os_auth', 'postgres')),
    actor_type          TEXT NOT NULL
                            CHECK (actor_type IN ('user', 'api_client', 'agent', 'system', 'os_admin', 'db_admin')),
    actor_user_id       UUID REFERENCES users(id),
    actor_api_client_id UUID REFERENCES api_clients(id),
    actor_label         TEXT,                     -- e.g. 'ssh:ops1', 'pg:aegis_owner', agent id
    action              TEXT NOT NULL,            -- e.g. 'patch.deploy.create', 'user.login'
    target_type         TEXT,
    target_id           UUID,
    details             JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address          INET,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_log_actor_user ON audit_log(actor_user_id);
CREATE INDEX idx_audit_log_target ON audit_log(target_type, target_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);

CREATE OR REPLACE FUNCTION reject_audit_log_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION reject_audit_log_mutation();

CREATE TRIGGER trg_audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_log_mutation();
-- Limit, stated plainly: a Postgres superuser can still disable triggers. That is why the
-- app must never connect as owner/superuser (see 0004_db_roles.sql) and why audit events
-- should also be shipped off-box.


-- -------------------------------------------------------------------------------------
-- 2. SIGNING KEYS  (Security Review: 12-month rotation, 30-day dual-key overlap)
-- -------------------------------------------------------------------------------------
-- Only the PUBLIC key is stored here. The private key stays in Vault; vault_key_ref points
-- to it. The license-signing key is NOT here - its public key is embedded in the binary.

CREATE TABLE signing_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_purpose     TEXT NOT NULL CHECK (key_purpose IN ('command_signing', 'manifest_signing')),
    algorithm       TEXT NOT NULL DEFAULT 'ed25519' CHECK (algorithm = 'ed25519'),
    public_key      TEXT NOT NULL UNIQUE,         -- base64
    vault_key_ref   TEXT NOT NULL,                -- e.g. 'transit/keys/aegis-command-2026'
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'active', 'retiring', 'retired', 'compromised')),
    activated_at    TIMESTAMPTZ,
    retiring_since  TIMESTAMPTZ,
    overlap_ends_at TIMESTAMPTZ,                  -- end of the dual-key window
    retired_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (status <> 'retiring' OR overlap_ends_at IS NOT NULL)
);

-- Exactly one active key per purpose.
CREATE UNIQUE INDEX uq_signing_keys_one_active ON signing_keys(key_purpose) WHERE status = 'active';

-- The key set agents should currently trust: the active key plus any retiring key still
-- inside its overlap window. 'compromised' is never trusted, even inside a window.
CREATE VIEW agent_trusted_signing_keys AS
SELECT id, key_purpose, public_key, status, overlap_ends_at
FROM signing_keys
WHERE status = 'active'
   OR (status = 'retiring' AND overlap_ends_at > now());


-- -------------------------------------------------------------------------------------
-- 3. SITES & DEVICE GROUPS  (ADR 3.4 - peer-cache model)
-- -------------------------------------------------------------------------------------

CREATE TABLE sites (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    region              TEXT,
    bandwidth_tier      TEXT NOT NULL DEFAULT 'lan'
                            CHECK (bandwidth_tier IN ('lan', 'wan_good', 'wan_constrained')),
    peer_cache_enabled  BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    parent_group_id UUID REFERENCES device_groups(id),
    site_id         UUID REFERENCES sites(id),
    group_type      TEXT NOT NULL DEFAULT 'custom'
                        CHECK (group_type IN ('ad_ou', 'ip_range', 'tag', 'custom')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_device_groups_parent ON device_groups(parent_group_id);
CREATE INDEX idx_device_groups_site ON device_groups(site_id);


-- -------------------------------------------------------------------------------------
-- 4. ENROLLMENT, DEVICES, AGENTS, CERTIFICATES & LAAC
-- -------------------------------------------------------------------------------------

CREATE TABLE enrollment_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash          TEXT NOT NULL UNIQUE,
    scope               JSONB NOT NULL DEFAULT '{}'::jsonb,   -- e.g. {"group_id": "...", "site_id": "..."}
    max_uses            INTEGER NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    use_count           INTEGER NOT NULL DEFAULT 0,
    created_by_user_id  UUID REFERENCES users(id),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (use_count <= max_uses)
);

CREATE TABLE devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname            TEXT NOT NULL,
    os_family           TEXT NOT NULL CHECK (os_family IN ('windows', 'linux', 'macos')),
    os_version          TEXT,
    os_edition          TEXT,
    management_type     TEXT NOT NULL DEFAULT 'agent'
                            CHECK (management_type IN ('agent', 'agentless')),
    device_class        TEXT NOT NULL DEFAULT 'workstation'
                            CHECK (device_class IN ('workstation', 'server')),
    site_id             UUID REFERENCES sites(id),
    primary_group_id    UUID REFERENCES device_groups(id),
    cpu_model           TEXT,
    ram_gb              NUMERIC(6,2),
    disk_capacity_gb    NUMERIC(10,2),
    manufacturer        TEXT,
    model               TEXT,
    serial_tag          TEXT,
    warranty_status     TEXT,
    warranty_checked_at TIMESTAMPTZ,
    status              TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'decommissioned', 'unmanaged')),
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_devices_site ON devices(site_id);
CREATE INDEX idx_devices_primary_group ON devices(primary_group_id);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_last_seen ON devices(last_seen_at);
CREATE TRIGGER trg_devices_updated_at BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE device_group_membership (
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    group_id    UUID NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, group_id)
);
CREATE INDEX idx_dgm_group ON device_group_membership(group_id);

CREATE TABLE agents (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id               UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    agent_version           TEXT NOT NULL,
    install_method          TEXT NOT NULL
                                CHECK (install_method IN ('winrm_ssh_push', 'gpo_login_script', 'self_install_link', 'third_party_rmm', 'offline_installer')),
    enrollment_token_id     UUID REFERENCES enrollment_tokens(id),
    hardware_bound_key_id   TEXT,                 -- TPM-backed key reference where available
    is_peer_cache_elected   BOOLEAN NOT NULL DEFAULT false,
    revoked_at              TIMESTAMPTZ,          -- whole-identity kill switch
    revoked_reason          TEXT,
    enrolled_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat_at       TIMESTAMPTZ
);
CREATE INDEX idx_agents_device ON agents(device_id);
-- At most one live (non-revoked) agent identity per device.
CREATE UNIQUE INDEX uq_agents_one_live_per_device ON agents(device_id) WHERE revoked_at IS NULL;

-- Certs are short-lived and auto-rotated, so one agent has many certs over time.
-- Revocation answer from the Security Review discussion: agents connect OUTBOUND, so the
-- server checks this table during every mTLS handshake. An agent that was offline when its
-- cert was revoked is simply refused at its next connect - it doesn't need to "find out".
CREATE TABLE agent_certificates (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id            UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    serial_number       TEXT NOT NULL UNIQUE,
    fingerprint_sha256  TEXT NOT NULL UNIQUE,
    not_before          TIMESTAMPTZ NOT NULL,
    not_after           TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revoked_reason      TEXT,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (not_after > not_before)
);
CREATE INDEX idx_agent_certs_agent ON agent_certificates(agent_id);
CREATE INDEX idx_agent_certs_revoked ON agent_certificates(fingerprint_sha256) WHERE revoked_at IS NOT NULL;

-- LAAC: which local users/groups may talk to the agent's IPC channel. Signed like a command.
CREATE TABLE agent_local_acl_policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    target_group_id     UUID REFERENCES device_groups(id),   -- NULL = fleet-wide default
    allowed_principals  JSONB NOT NULL,     -- e.g. {"windows_groups": ["Administrators"], "linux_groups": ["wheel"]}
    policy_version      INTEGER NOT NULL DEFAULT 1,
    signature_ed25519   TEXT NOT NULL,
    signing_key_id      UUID NOT NULL REFERENCES signing_keys(id),
    created_by_user_id  UUID REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_group_id, policy_version)
);


-- -------------------------------------------------------------------------------------
-- 5. SIGNED AGENT COMMANDS  (ADR 3.6 signed commands, ADR 3.9 idempotency, Run-As audit)
-- -------------------------------------------------------------------------------------

CREATE TABLE agent_commands (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id                UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    command_type            TEXT NOT NULL,     -- e.g. 'patch.install', 'software.install', 'scan.run', 'acl.apply'
    payload                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    run_as_user             TEXT,              -- Run-As target context; NULL = agent service account
    idempotency_key         TEXT NOT NULL UNIQUE,   -- a retried command can never execute twice
    signature_ed25519       TEXT NOT NULL,
    signing_key_id          UUID NOT NULL REFERENCES signing_keys(id),
    issued_by_user_id       UUID REFERENCES users(id),
    issued_by_api_client_id UUID REFERENCES api_clients(id),
    source_job_type         TEXT CHECK (source_job_type IN ('patch_deployment', 'software_deployment', 'vulnerability_scan')),
    source_job_id           UUID,
    status                  TEXT NOT NULL DEFAULT 'queued'
                                CHECK (status IN ('queued', 'dispatched', 'acknowledged', 'succeeded', 'failed', 'expired', 'rejected_signature')),
    result                  JSONB,
    expires_at              TIMESTAMPTZ NOT NULL,
    issued_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at           TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ
);
CREATE INDEX idx_agent_commands_agent_status ON agent_commands(agent_id, status);
CREATE INDEX idx_agent_commands_source_job ON agent_commands(source_job_type, source_job_id);

-- "Run-As ... fully audited" enforced by the database, not left to app discipline.
CREATE OR REPLACE FUNCTION audit_run_as_command() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (source, actor_type, actor_user_id, actor_api_client_id,
                           action, target_type, target_id, details)
    VALUES ('application',
            CASE WHEN NEW.issued_by_api_client_id IS NOT NULL THEN 'api_client'
                 WHEN NEW.issued_by_user_id IS NOT NULL THEN 'user'
                 ELSE 'system' END,
            NEW.issued_by_user_id,
            NEW.issued_by_api_client_id,
            'agent.command.run_as', 'agent', NEW.agent_id,
            jsonb_build_object('command_id', NEW.id,
                               'command_type', NEW.command_type,
                               'run_as_user', NEW.run_as_user));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_agent_commands_audit_run_as
    AFTER INSERT ON agent_commands
    FOR EACH ROW WHEN (NEW.run_as_user IS NOT NULL)
    EXECUTE FUNCTION audit_run_as_command();


-- -------------------------------------------------------------------------------------
-- 6. AGENT HEARTBEATS  (becomes a hypertable in 0002_timescale.sql)
-- -------------------------------------------------------------------------------------

CREATE TABLE agent_heartbeats (
    time                TIMESTAMPTZ NOT NULL DEFAULT now(),
    agent_id            UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cpu_pct             REAL,
    ram_pct             REAL,
    disk_free_gb        REAL,
    agent_version       TEXT,
    connection_state    TEXT NOT NULL DEFAULT 'connected'
                            CHECK (connection_state IN ('connected', 'degraded', 'disconnected'))
);
CREATE INDEX idx_heartbeats_device_time ON agent_heartbeats(device_id, time DESC);


-- -------------------------------------------------------------------------------------
-- 7. PATCH MANAGEMENT
-- -------------------------------------------------------------------------------------

CREATE TABLE patch_catalog (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor              TEXT NOT NULL,
    product             TEXT NOT NULL,
    kb_or_advisory_id   TEXT,                       -- e.g. 'KB5041288', 'RHSA-2026:1234'
    title               TEXT NOT NULL,
    cve_ids             TEXT[] NOT NULL DEFAULT '{}',
    severity            TEXT NOT NULL DEFAULT 'unrated'
                            CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unrated')),
    release_date        DATE,
    is_esu              BOOLEAN NOT NULL DEFAULT false,
    superseded_by_id    UUID REFERENCES patch_catalog(id),   -- supersedence chain
    sha256_hash         TEXT NOT NULL,
    source_url          TEXT,
    ingested_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_patch_catalog_product ON patch_catalog(vendor, product);
CREATE INDEX idx_patch_catalog_superseded_by ON patch_catalog(superseded_by_id);
CREATE INDEX idx_patch_catalog_cve_ids ON patch_catalog USING GIN (cve_ids);

CREATE TABLE patch_prerequisites (
    patch_id                UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    prerequisite_patch_id   UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    PRIMARY KEY (patch_id, prerequisite_patch_id),
    CHECK (patch_id <> prerequisite_patch_id)
);

CREATE TABLE patch_deployments (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    TEXT NOT NULL,
    created_by_user_id      UUID REFERENCES users(id),
    target_group_id         UUID REFERENCES device_groups(id),
    patch_ids               UUID[] NOT NULL,
    window_start_time       TIME,
    window_end_time         TIME,
    allowed_days            TEXT[] DEFAULT '{mon,tue,wed,thu,fri,sat,sun}',
    rollout_strategy        TEXT NOT NULL DEFAULT 'phased'
                                CHECK (rollout_strategy IN ('phased', 'all_at_once', 'pilot_only')),
    pilot_percentage        INTEGER CHECK (pilot_percentage BETWEEN 1 AND 100),
    reboot_behavior         TEXT NOT NULL DEFAULT 'user_deferred'
                                CHECK (reboot_behavior IN ('immediate', 'user_deferred', 'no_reboot')),
    reboot_defer_minutes    INTEGER,
    retry_count             INTEGER NOT NULL DEFAULT 3,
    status                  TEXT NOT NULL DEFAULT 'scheduled'
                                CHECK (status IN ('scheduled', 'running', 'completed', 'failed', 'cancelled')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_patch_deployments_group ON patch_deployments(target_group_id);
CREATE INDEX idx_patch_deployments_status ON patch_deployments(status);

CREATE TABLE patch_deployment_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id   UUID NOT NULL REFERENCES patch_deployments(id) ON DELETE CASCADE,
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    patch_id        UUID NOT NULL REFERENCES patch_catalog(id),
    status          TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'in_progress', 'succeeded', 'failed', 'rolled_back')),
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    UNIQUE (deployment_id, device_id, patch_id)
);
CREATE INDEX idx_pdr_device ON patch_deployment_results(device_id);
CREATE INDEX idx_pdr_deployment_status ON patch_deployment_results(deployment_id, status);

CREATE TABLE patch_exceptions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id           UUID REFERENCES devices(id) ON DELETE CASCADE,
    device_group_id     UUID REFERENCES device_groups(id) ON DELETE CASCADE,
    patch_id            UUID NOT NULL REFERENCES patch_catalog(id),
    reason              TEXT NOT NULL,
    approved_by_user_id UUID NOT NULL REFERENCES users(id),
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (device_id IS NOT NULL OR device_group_id IS NOT NULL)
);
CREATE INDEX idx_patch_exceptions_patch ON patch_exceptions(patch_id);


-- -------------------------------------------------------------------------------------
-- 8. SOFTWARE DISTRIBUTION
-- -------------------------------------------------------------------------------------

CREATE TABLE software_packages (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    version             TEXT NOT NULL,
    package_format      TEXT NOT NULL
                            CHECK (package_format IN ('msi', 'exe', 'dmg', 'pkg', 'deb', 'rpm', 'script')),
    sha256_hash         TEXT NOT NULL,
    size_bytes          BIGINT,
    install_command     TEXT,
    uninstall_command   TEXT,
    silent_args         TEXT,
    uploaded_by_user_id UUID REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name, version, package_format)
);

CREATE TABLE software_deployments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id          UUID NOT NULL REFERENCES software_packages(id),
    action              TEXT NOT NULL DEFAULT 'install'
                            CHECK (action IN ('install', 'update', 'remove')),
    target_group_id     UUID REFERENCES device_groups(id),
    created_by_user_id  UUID REFERENCES users(id),
    schedule_type       TEXT NOT NULL DEFAULT 'immediate'
                            CHECK (schedule_type IN ('immediate', 'scheduled', 'recurring')),
    scheduled_at        TIMESTAMPTZ,
    recurrence_cron     TEXT,
    status              TEXT NOT NULL DEFAULT 'scheduled'
                            CHECK (status IN ('scheduled', 'running', 'completed', 'failed', 'cancelled')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_software_deployments_group ON software_deployments(target_group_id);

CREATE TABLE software_deployment_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id   UUID NOT NULL REFERENCES software_deployments(id) ON DELETE CASCADE,
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'in_progress', 'succeeded', 'failed')),
    progress_pct    SMALLINT NOT NULL DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    UNIQUE (deployment_id, device_id)
);
CREATE INDEX idx_sdr_device ON software_deployment_results(device_id);


-- -------------------------------------------------------------------------------------
-- 9. VULNERABILITY SCANNER
-- -------------------------------------------------------------------------------------

CREATE TABLE cve_catalog (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT,
    cvss_score      NUMERIC(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    severity        TEXT NOT NULL DEFAULT 'unrated'
                        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unrated')),
    is_kev          BOOLEAN NOT NULL DEFAULT false,
    published_at    DATE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vulnerability_findings (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id               UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cve_id                  TEXT NOT NULL REFERENCES cve_catalog(cve_id),
    affected_product        TEXT NOT NULL,
    remediation_patch_id    UUID REFERENCES patch_catalog(id),
    risk_score              NUMERIC(5,2),
    status                  TEXT NOT NULL DEFAULT 'open'
                                CHECK (status IN ('open', 'remediated', 'accepted_risk')),
    detected_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at             TIMESTAMPTZ,
    UNIQUE (device_id, cve_id, affected_product)
);
CREATE INDEX idx_vuln_findings_device ON vulnerability_findings(device_id);
CREATE INDEX idx_vuln_findings_cve ON vulnerability_findings(cve_id);
CREATE INDEX idx_vuln_findings_open ON vulnerability_findings(status) WHERE status = 'open';

CREATE TABLE vulnerability_scan_jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_group_id     UUID REFERENCES device_groups(id),
    scope               TEXT NOT NULL DEFAULT 'combined'
                            CHECK (scope IN ('os_only', 'apps_only', 'combined')),
    schedule_type       TEXT NOT NULL DEFAULT 'on_demand'
                            CHECK (schedule_type IN ('on_demand', 'daily', 'weekly')),
    created_by_user_id  UUID REFERENCES users(id),
    status              TEXT NOT NULL DEFAULT 'scheduled'
                            CHECK (status IN ('scheduled', 'running', 'completed', 'failed')),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Nightly open-count snapshot per group (RFP: exposure trend reporting). Hypertable in 0002.
CREATE TABLE vulnerability_exposure_snapshots (
    time            TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_group_id UUID REFERENCES device_groups(id),   -- NULL = whole fleet
    severity        TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unrated')),
    open_count      INTEGER NOT NULL CHECK (open_count >= 0)
);
CREATE INDEX idx_vuln_exposure_group_time ON vulnerability_exposure_snapshots(device_group_id, time DESC);


-- -------------------------------------------------------------------------------------
-- 10. DEX-LITE  (becomes a hypertable in 0002_timescale.sql)
-- -------------------------------------------------------------------------------------

CREATE TABLE device_dex_metrics (
    time                TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    boot_time_seconds   REAL,
    app_crash_count     INTEGER NOT NULL DEFAULT 0,
    cpu_pct             REAL,
    ram_pct             REAL,
    disk_pct            REAL,
    experience_score    SMALLINT CHECK (experience_score BETWEEN 0 AND 100)
);
CREATE INDEX idx_dex_metrics_device_time ON device_dex_metrics(device_id, time DESC);


-- -------------------------------------------------------------------------------------
-- 11. HARDWARE & SOFTWARE INVENTORY
-- -------------------------------------------------------------------------------------

CREATE TABLE software_inventory (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    app_name        TEXT NOT NULL,
    app_version     TEXT,
    publisher       TEXT,
    install_date    DATE,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_authorized   BOOLEAN,            -- NULL = not yet evaluated against allow/deny rules
    removed_at      TIMESTAMPTZ,
    UNIQUE (device_id, app_name, app_version)
);
CREATE INDEX idx_sw_inventory_device ON software_inventory(device_id) WHERE removed_at IS NULL;
CREATE INDEX idx_sw_inventory_app_name ON software_inventory(app_name);

CREATE TABLE inventory_change_log (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    change_type     TEXT NOT NULL
                        CHECK (change_type IN ('software_installed', 'software_removed', 'hardware_changed')),
    details         JSONB NOT NULL DEFAULT '{}'::jsonb,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_inventory_change_device ON inventory_change_log(device_id, detected_at DESC);

CREATE TABLE allowlist_denylist_rules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_name_pattern    TEXT NOT NULL,
    list_type           TEXT NOT NULL CHECK (list_type IN ('allow', 'deny')),
    created_by_user_id  UUID REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- -------------------------------------------------------------------------------------
-- 12. CONTENT INTEGRITY  (ADR 3.4 - locked spec)
-- -------------------------------------------------------------------------------------

CREATE TABLE content_manifests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content_type        TEXT NOT NULL CHECK (content_type IN ('patch', 'software_package')),
    content_id          UUID NOT NULL,     -- patch_catalog.id or software_packages.id (polymorphic, app-enforced)
    version             TEXT NOT NULL,
    sha256_hash         TEXT NOT NULL,
    target_scope        JSONB NOT NULL DEFAULT '{}'::jsonb,
    signature_ed25519   TEXT NOT NULL,
    signing_key_id      UUID NOT NULL REFERENCES signing_keys(id),   -- which key signed it (rotation-safe)
    source_verified_at  TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_content_manifests_content ON content_manifests(content_type, content_id);

CREATE TABLE content_integrity_failures (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    manifest_id     UUID REFERENCES content_manifests(id),
    device_id       UUID REFERENCES devices(id),
    failure_stage   TEXT NOT NULL CHECK (failure_stage IN ('ingestion', 'peer_cache_hop', 'pre_install')),
    expected_hash   TEXT,
    actual_hash     TEXT,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_content_failures_device ON content_integrity_failures(device_id);


-- -------------------------------------------------------------------------------------
-- 13. LICENSE / ENTITLEMENT  (Security Review: signed file, validated offline)
-- -------------------------------------------------------------------------------------
-- This row is a CACHE, not the source of trust. The server re-verifies license_file against
-- the public key embedded in its binary on every start, so editing max_devices here directly
-- changes nothing.

CREATE TABLE licenses (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id              TEXT NOT NULL UNIQUE,       -- id from inside the signed file
    licensee                TEXT NOT NULL,
    max_devices             INTEGER NOT NULL CHECK (max_devices > 0),
    modules_enabled         TEXT[] NOT NULL,            -- e.g. {patch,software,va,dex,inventory}
    issued_at               TIMESTAMPTZ NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    license_file            TEXT NOT NULL,              -- full signed file
    status                  TEXT NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'superseded', 'expired', 'invalid')),
    installed_by_user_id    UUID REFERENCES users(id),
    installed_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > issued_at)
);
CREATE UNIQUE INDEX uq_licenses_one_active ON licenses(status) WHERE status = 'active';


-- -------------------------------------------------------------------------------------
-- 14. BACKUP RUNS  (Security Review: encrypted backups, dedicated backup_operator role)
-- -------------------------------------------------------------------------------------
-- Operational record only. Stored credentials/keys never go here.

CREATE TABLE backup_runs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_type             TEXT NOT NULL CHECK (backup_type IN ('full', 'incremental', 'wal_archive')),
    status                  TEXT NOT NULL DEFAULT 'running'
                                CHECK (status IN ('running', 'succeeded', 'failed')),
    storage_location        TEXT NOT NULL,              -- path / bucket reference
    encryption              TEXT NOT NULL DEFAULT 'aes-256-gcm'
                                CHECK (encryption = 'aes-256-gcm'),   -- unencrypted backups are not representable
    size_bytes              BIGINT,
    checksum_sha256         TEXT,
    initiated_by_user_id    UUID REFERENCES users(id),
    started_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at            TIMESTAMPTZ,
    restore_tested_at       TIMESTAMPTZ,                -- last time this backup was actually restored as a test
    error_message           TEXT
);
CREATE INDEX idx_backup_runs_started ON backup_runs(started_at DESC);


-- -------------------------------------------------------------------------------------
-- 15. UNIFIED JOBS VIEW  (console "Jobs" screen)
-- -------------------------------------------------------------------------------------

CREATE VIEW jobs_overview AS
SELECT pd.id, 'patch_deployment'::text AS job_type, pd.name AS label, pd.status, pd.created_at
FROM patch_deployments pd
UNION ALL
SELECT sd.id, 'software_deployment'::text, sp.name || ' ' || sp.version, sd.status, sd.created_at
FROM software_deployments sd
JOIN software_packages sp ON sp.id = sd.package_id
UNION ALL
SELECT vs.id, 'vulnerability_scan'::text, 'Vulnerability scan (' || vs.scope || ')', vs.status, vs.created_at
FROM vulnerability_scan_jobs vs;
