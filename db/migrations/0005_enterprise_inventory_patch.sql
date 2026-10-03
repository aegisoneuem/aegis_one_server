-- =====================================================================================
-- AEGIS ONE - Database Schema v3
-- File 5: 0005_enterprise_inventory_patch.sql
-- Runs on plain PostgreSQL 14+, AFTER 0001-0004. Purely ADDITIVE: new tables, new
-- columns, one widened CHECK constraint. Nothing is dropped, no data is touched.
--
-- What this adds (enterprise-grade device inventory + patch compliance):
--   A. Stable device identity + rich core attributes (OS build/UBR, arch, BIOS, domain,
--      reboot state, criticality, owner/BU) on the devices table
--   B. Repeating hardware as child tables: network interfaces, IP addresses (subnet
--      searchable), disks + encryption, security posture (TPM, Secure Boot, AV, firewall)
--   C. Extensible custom attributes (like BigFix properties / Tanium sensors)
--   D. Dynamic (rule-based) device groups + RBAC scoping (user sees only their groups)
--   E. Enterprise patch catalog: classification, arch, reboot behaviour, vendor update id,
--      CVE + supersedence as proper junction tables, patch files, applicability rules
--   F. device_patch_state - THE compliance table: per device, per applicable patch,
--      missing / installed / pending_reboot / failed, with SLA due date. Hash-partitioned.
--   G. Patch policies (SLA by severity, KEV override), maintenance + blackout windows,
--      deployment rings, per-ring approvals, deployment auto-pause
--   H. Compliance views (current state) + daily snapshot tables and function
--      (point-in-time history for auditors - "what was compliance on 31 March?")
-- =====================================================================================


-- -------------------------------------------------------------------------------------
-- A. DEVICE IDENTITY & CORE ATTRIBUTES
-- -------------------------------------------------------------------------------------
-- Identity note: hostnames collide and change, and cloned VMs / golden images can share
-- an SMBIOS UUID. So the agent's enrolled identity (agents + agent_certificates) stays the
-- primary identity; the hardware ids below are for DUPLICATE DETECTION, not uniqueness.

ALTER TABLE devices
    ADD COLUMN smbios_uuid              TEXT,      -- Win32_ComputerSystemProduct.UUID / dmidecode
    ADD COLUMN machine_id               TEXT,      -- Windows MachineGuid, /etc/machine-id, macOS IOPlatformUUID
    ADD COLUMN fqdn                     TEXT,
    ADD COLUMN domain_name              TEXT,
    ADD COLUMN is_domain_joined         BOOLEAN,
    ADD COLUMN architecture             TEXT CHECK (architecture IN ('x86', 'x64', 'arm64')),
    ADD COLUMN os_build                 TEXT,      -- e.g. Windows '22631', macOS '23F79'
    ADD COLUMN os_ubr                   INTEGER,   -- Windows Update Build Revision - key for applicability
    ADD COLUMN kernel_version           TEXT,      -- Linux / macOS kernel
    ADD COLUMN os_install_date          DATE,
    ADD COLUMN bios_vendor              TEXT,
    ADD COLUMN bios_version             TEXT,
    ADD COLUMN bios_release_date        DATE,
    ADD COLUMN time_zone                TEXT,
    ADD COLUMN locale                   TEXT,
    ADD COLUMN last_boot_at             TIMESTAMPTZ,
    ADD COLUMN pending_reboot           BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN pending_reboot_reason    TEXT,      -- 'windows_update', 'cbs', 'file_rename', 'kernel' ...
    ADD COLUMN last_logged_on_user      TEXT,      -- PII: needed for support/targeting; keep access limited
    ADD COLUMN criticality              TEXT NOT NULL DEFAULT 'medium'
                                            CHECK (criticality IN ('low', 'medium', 'high', 'mission_critical')),
    ADD COLUMN environment              TEXT CHECK (environment IN ('production', 'staging', 'development', 'dr')),
    ADD COLUMN business_unit            TEXT,
    ADD COLUMN owner_email              TEXT,
    ADD COLUMN location                 TEXT,
    ADD COLUMN tags                     TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN last_inventory_at        TIMESTAMPTZ,
    ADD COLUMN last_patch_scan_at       TIMESTAMPTZ,  -- stale scan => compliance 'unknown', never 'compliant'
    ADD COLUMN last_patch_scan_status   TEXT CHECK (last_patch_scan_status IN ('succeeded', 'failed', 'partial'));

CREATE INDEX idx_devices_smbios_uuid ON devices(smbios_uuid) WHERE smbios_uuid IS NOT NULL;
CREATE INDEX idx_devices_machine_id  ON devices(machine_id)  WHERE machine_id IS NOT NULL;
CREATE INDEX idx_devices_hostname    ON devices(lower(hostname));
CREATE INDEX idx_devices_os          ON devices(os_family, os_version, os_build);
CREATE INDEX idx_devices_tags        ON devices USING GIN (tags);
CREATE INDEX idx_devices_criticality ON devices(criticality);


-- -------------------------------------------------------------------------------------
-- B. HARDWARE CHILD TABLES & SECURITY POSTURE
-- -------------------------------------------------------------------------------------

CREATE TABLE device_network_interfaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,             -- 'Ethernet0', 'eth0', 'en0'
    mac_address     MACADDR,
    interface_type  TEXT CHECK (interface_type IN ('ethernet', 'wifi', 'vpn', 'virtual', 'other')),
    is_up           BOOLEAN,
    speed_mbps      INTEGER,
    dhcp_enabled    BOOLEAN,
    gateway         INET,
    dns_servers     INET[],
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, name)
);
CREATE INDEX idx_dni_mac ON device_network_interfaces(mac_address);

-- One row per IP, so "all devices in 10.20.0.0/16" is an indexed query (IP-range groups,
-- site auto-assignment for the peer-cache model).
CREATE TABLE device_ip_addresses (
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_id    UUID REFERENCES device_network_interfaces(id) ON DELETE CASCADE,
    ip              INET NOT NULL,
    is_primary      BOOLEAN NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, ip)
);
CREATE INDEX idx_dip_ip_gist ON device_ip_addresses USING gist (ip inet_ops);

CREATE TABLE device_disks (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mount_point         TEXT NOT NULL,         -- 'C:', '/', '/var'
    filesystem          TEXT,
    size_gb             NUMERIC(10,2),
    free_gb             NUMERIC(10,2),
    encryption_type     TEXT NOT NULL DEFAULT 'unknown'
                            CHECK (encryption_type IN ('bitlocker', 'filevault', 'luks', 'other', 'none', 'unknown')),
    encryption_status   TEXT NOT NULL DEFAULT 'unknown'
                            CHECK (encryption_status IN ('encrypted', 'encrypting', 'decrypted', 'unknown')),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, mount_point)
);

CREATE TABLE device_security_posture (
    device_id                   UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    tpm_present                 BOOLEAN,
    tpm_version                 TEXT,
    secure_boot_enabled         BOOLEAN,
    firewall_enabled            BOOLEAN,
    av_product                  TEXT,
    av_realtime_enabled         BOOLEAN,
    av_signatures_updated_at    TIMESTAMPTZ,
    all_disks_encrypted         BOOLEAN,
    local_admin_count           INTEGER,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- -------------------------------------------------------------------------------------
-- C. EXTENSIBLE CUSTOM ATTRIBUTES
-- -------------------------------------------------------------------------------------
-- Admins define new attributes (registry value, WMI/CIM query, file version, script
-- output) without a schema change. Collection specs that run code on endpoints must be
-- dispatched as SIGNED agent_commands - never as raw strings the agent executes blindly.

CREATE TABLE attribute_definitions (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attr_key                    TEXT NOT NULL UNIQUE,     -- 'java_version', 'sccm_client_present'
    display_name                TEXT NOT NULL,
    data_type                   TEXT NOT NULL
                                    CHECK (data_type IN ('string', 'integer', 'decimal', 'boolean', 'datetime', 'json')),
    source                      TEXT NOT NULL
                                    CHECK (source IN ('builtin', 'registry', 'wmi', 'file', 'script', 'plist', 'command')),
    collection_spec             JSONB NOT NULL DEFAULT '{}'::jsonb,
    os_families                 TEXT[] NOT NULL DEFAULT '{windows,linux,macos}',
    refresh_interval_seconds    INTEGER NOT NULL DEFAULT 86400 CHECK (refresh_interval_seconds >= 300),
    is_enabled                  BOOLEAN NOT NULL DEFAULT true,
    created_by_user_id          UUID REFERENCES users(id),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Typed value columns (not one TEXT blob) so range/equality filters use indexes.
CREATE TABLE device_attribute_values (
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    attribute_id    UUID NOT NULL REFERENCES attribute_definitions(id) ON DELETE CASCADE,
    value_text      TEXT,
    value_num       NUMERIC,
    value_bool      BOOLEAN,
    value_ts        TIMESTAMPTZ,
    value_json      JSONB,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, attribute_id)
);
CREATE INDEX idx_dav_text ON device_attribute_values(attribute_id, value_text);
CREATE INDEX idx_dav_num  ON device_attribute_values(attribute_id, value_num);


-- -------------------------------------------------------------------------------------
-- D. DYNAMIC GROUPS & RBAC SCOPING
-- -------------------------------------------------------------------------------------

ALTER TABLE device_groups
    ADD COLUMN membership_type   TEXT NOT NULL DEFAULT 'static'
                                     CHECK (membership_type IN ('static', 'dynamic')),
    ADD COLUMN membership_rule   JSONB,   -- e.g. {"all":[{"field":"os_family","op":"eq","value":"windows"},{"field":"device_class","op":"eq","value":"server"}]}
    ADD COLUMN rule_evaluated_at TIMESTAMPTZ,
    ADD CONSTRAINT chk_dynamic_group_has_rule
        CHECK (membership_type = 'static' OR membership_rule IS NOT NULL);

ALTER TABLE device_group_membership
    ADD COLUMN source TEXT NOT NULL DEFAULT 'static' CHECK (source IN ('static', 'dynamic'));

-- Enterprise RBAC: "Mumbai operators only see and act on Mumbai devices".
-- No row for a user = unscoped (sees everything their role allows). Enforced by the app;
-- Postgres Row-Level Security can be layered on later if required.
CREATE TABLE user_scopes (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_group_id UUID NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    granted_by_user_id UUID REFERENCES users(id),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_group_id)
);


-- -------------------------------------------------------------------------------------
-- E. ENTERPRISE PATCH CATALOG
-- -------------------------------------------------------------------------------------

ALTER TABLE patch_catalog
    ADD COLUMN vendor_update_id     TEXT,        -- Windows UpdateID GUID, RHSA/USN id, vendor release id
    ADD COLUMN revision             INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN classification       TEXT NOT NULL DEFAULT 'security'
                                        CHECK (classification IN ('security', 'critical', 'update_rollup', 'service_pack',
                                                                  'feature_pack', 'driver', 'definition', 'bugfix',
                                                                  'enhancement', 'third_party')),
    ADD COLUMN os_family            TEXT CHECK (os_family IN ('windows', 'linux', 'macos', 'cross_platform')),
    ADD COLUMN architectures        TEXT[] NOT NULL DEFAULT '{}',   -- {x64,arm64}
    ADD COLUMN reboot_behavior      TEXT NOT NULL DEFAULT 'may'
                                        CHECK (reboot_behavior IN ('always', 'never', 'may')),
    ADD COLUMN is_uninstallable     BOOLEAN NOT NULL DEFAULT false,  -- rollback possible?
    ADD COLUMN vendor_severity      TEXT,        -- vendor's own rating, kept alongside normalized severity
    ADD COLUMN max_cvss             NUMERIC(3,1),
    ADD COLUMN has_kev              BOOLEAN NOT NULL DEFAULT false,  -- any linked CVE on CISA KEV (denormalized)
    ADD COLUMN package_name         TEXT,        -- Linux: 'openssl'
    ADD COLUMN package_version      TEXT,        -- Linux: '3.0.2-0ubuntu1.18' (epoch:version-release)
    ADD COLUMN language             TEXT,
    ADD COLUMN is_withdrawn         BOOLEAN NOT NULL DEFAULT false,  -- vendor pulled / expired it
    ADD COLUMN kb_article_url       TEXT;

CREATE UNIQUE INDEX uq_patch_vendor_update ON patch_catalog(vendor, vendor_update_id, revision)
    WHERE vendor_update_id IS NOT NULL;
CREATE INDEX idx_patch_catalog_class ON patch_catalog(os_family, classification, severity);

-- Replaces patch_catalog.cve_ids (array). Ingest CVEs into cve_catalog first.
CREATE TABLE patch_cves (
    patch_id    UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    cve_id      TEXT NOT NULL REFERENCES cve_catalog(cve_id),
    PRIMARY KEY (patch_id, cve_id)
);
CREATE INDEX idx_patch_cves_cve ON patch_cves(cve_id);

-- Replaces patch_catalog.superseded_by_id: one cumulative update supersedes MANY older ones.
CREATE TABLE patch_supersedence (
    superseding_patch_id    UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    superseded_patch_id     UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    PRIMARY KEY (superseding_patch_id, superseded_patch_id),
    CHECK (superseding_patch_id <> superseded_patch_id)
);
CREATE INDEX idx_patch_supersedence_old ON patch_supersedence(superseded_patch_id);
-- Deprecated (kept, not dropped): patch_catalog.cve_ids and patch_catalog.superseded_by_id.
-- Drop them in a later migration once no code reads them.

-- One patch can ship several files (per architecture / language).
CREATE TABLE patch_files (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id            UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    architecture        TEXT CHECK (architecture IN ('x86', 'x64', 'arm64', 'any')),
    language            TEXT,
    file_name           TEXT NOT NULL,
    size_bytes          BIGINT,
    sha256_hash         TEXT NOT NULL,
    download_url        TEXT,
    content_manifest_id UUID REFERENCES content_manifests(id),
    UNIQUE (patch_id, file_name)
);

-- Applicability for content the OS can't evaluate itself. Windows OS updates are evaluated
-- natively on the endpoint (Windows Update Agent / offline scan cab); Linux uses the package
-- manager. These rules cover third-party apps and anything needing extra conditions.
CREATE TABLE patch_applicability_rules (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id                UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    os_family               TEXT CHECK (os_family IN ('windows', 'linux', 'macos')),
    os_version_pattern      TEXT,          -- e.g. '10.0.%', '22.04'
    os_build_min            TEXT,
    os_build_max            TEXT,
    architecture            TEXT CHECK (architecture IN ('x86', 'x64', 'arm64')),
    product_name_pattern    TEXT,          -- matched against software_inventory.app_name, e.g. 'Google Chrome%'
    product_version_below   TEXT,          -- applicable if installed version < this
    extra_conditions        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_par_patch ON patch_applicability_rules(patch_id);

ALTER TABLE cve_catalog
    ADD COLUMN cvss_vector      TEXT,
    ADD COLUMN epss_score       NUMERIC(6,5) CHECK (epss_score BETWEEN 0 AND 1),   -- FIRST EPSS exploit probability
    ADD COLUMN epss_percentile  NUMERIC(6,5) CHECK (epss_percentile BETWEEN 0 AND 1),
    ADD COLUMN kev_added_at     DATE;


-- -------------------------------------------------------------------------------------
-- G. POLICIES, WINDOWS, RINGS, APPROVALS  (created before F because F references policies)
-- -------------------------------------------------------------------------------------

CREATE TABLE maintenance_windows (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL UNIQUE,
    time_zone           TEXT NOT NULL DEFAULT 'Asia/Kolkata',
    allowed_days        TEXT[] NOT NULL DEFAULT '{sat,sun}',
    start_time          TIME NOT NULL,
    duration_minutes    INTEGER NOT NULL CHECK (duration_minutes BETWEEN 15 AND 1440),
    -- Blackout = change freeze (e.g. month-end / quarter-end close in banks): NOTHING deploys.
    is_blackout         BOOLEAN NOT NULL DEFAULT false,
    valid_from          DATE,
    valid_until         DATE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE patch_policies (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                        TEXT NOT NULL UNIQUE,
    description                 TEXT,
    applies_to_group_id         UUID REFERENCES device_groups(id),  -- NULL = fleet-wide default
    priority                    INTEGER NOT NULL DEFAULT 100,        -- lower wins if a device matches several
    sla_days_critical           INTEGER NOT NULL DEFAULT 7,
    sla_days_high               INTEGER NOT NULL DEFAULT 14,
    sla_days_medium             INTEGER NOT NULL DEFAULT 30,
    sla_days_low                INTEGER NOT NULL DEFAULT 90,
    sla_days_kev                INTEGER NOT NULL DEFAULT 3,          -- known-exploited overrides severity
    in_scope_classifications    TEXT[] NOT NULL DEFAULT '{security,critical,update_rollup,third_party}',
    auto_approve_classifications TEXT[] NOT NULL DEFAULT '{}',
    maintenance_window_id       UUID REFERENCES maintenance_windows(id),
    is_enabled                  BOOLEAN NOT NULL DEFAULT true,
    created_by_user_id          UUID REFERENCES users(id),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (sla_days_kev <= sla_days_critical)
);

CREATE TABLE deployment_rings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,              -- 'Pilot', 'Early adopters', 'Broad'
    order_index     INTEGER NOT NULL UNIQUE,           -- 1 = first
    device_group_id UUID NOT NULL REFERENCES device_groups(id),
    soak_hours      INTEGER NOT NULL DEFAULT 24,       -- wait this long, healthy, before next ring
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE patch_approvals (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id            UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    ring_id             UUID NOT NULL REFERENCES deployment_rings(id) ON DELETE CASCADE,
    decision            TEXT NOT NULL DEFAULT 'pending'
                            CHECK (decision IN ('pending', 'approved', 'declined')),
    decided_by_user_id  UUID REFERENCES users(id),
    decided_at          TIMESTAMPTZ,
    reason              TEXT,
    change_ticket_ref   TEXT,               -- CAB / ServiceNow change number
    UNIQUE (patch_id, ring_id),
    CHECK (decision = 'pending' OR (decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL))
);

ALTER TABLE patch_deployments
    ADD COLUMN policy_id                UUID REFERENCES patch_policies(id),
    ADD COLUMN ring_id                  UUID REFERENCES deployment_rings(id),
    ADD COLUMN maintenance_window_id    UUID REFERENCES maintenance_windows(id),
    ADD COLUMN auto_pause_failure_pct   INTEGER CHECK (auto_pause_failure_pct BETWEEN 1 AND 100),
    ADD COLUMN paused_at                TIMESTAMPTZ,
    ADD COLUMN pause_reason             TEXT,
    DROP CONSTRAINT patch_deployments_status_check,
    ADD CONSTRAINT patch_deployments_status_check
        CHECK (status IN ('scheduled', 'running', 'paused', 'completed', 'failed', 'cancelled'));


-- -------------------------------------------------------------------------------------
-- F. DEVICE PATCH STATE - the compliance source of truth
-- -------------------------------------------------------------------------------------
-- One row per (device, APPLICABLE patch). Not-applicable patches are NOT stored - that is
-- what keeps this table at "devices x ~200" rows instead of "devices x whole catalog".
-- Written by scan results (agent or agentless), not by deployments: a patch installed by
-- hand, by WSUS, or by us all show up here the same way.
-- sla_due_at is set by the app when the patch is first detected missing, from the device's
-- winning patch_policy (severity days, or sla_days_kev if a linked CVE is known-exploited).

CREATE TABLE device_patch_state (
    device_id                   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    patch_id                    UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    state                       TEXT NOT NULL
                                    CHECK (state IN ('missing', 'installed', 'pending_reboot', 'failed', 'superseded')),
    detection_source            TEXT NOT NULL
                                    CHECK (detection_source IN ('agent_wua', 'agent_package_manager', 'agent_rule', 'agentless_scan')),
    policy_id                   UUID REFERENCES patch_policies(id),
    first_detected_missing_at   TIMESTAMPTZ,
    sla_due_at                  TIMESTAMPTZ,
    installed_at                TIMESTAMPTZ,
    last_evaluated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    install_attempts            INTEGER NOT NULL DEFAULT 0,
    last_error                  TEXT,
    PRIMARY KEY (device_id, patch_id)
) PARTITION BY HASH (device_id);

-- 16 hash partitions: ~100k devices x ~150 rows = ~15M rows, ~1M per partition.
DO $$
BEGIN
    FOR i IN 0..15 LOOP
        EXECUTE format(
            'CREATE TABLE device_patch_state_p%s PARTITION OF device_patch_state FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            lpad(i::text, 2, '0'), i);
    END LOOP;
END
$$;

CREATE INDEX idx_dps_patch_state ON device_patch_state(patch_id, state);
CREATE INDEX idx_dps_overdue     ON device_patch_state(sla_due_at) WHERE state IN ('missing', 'failed', 'pending_reboot');


-- -------------------------------------------------------------------------------------
-- H. COMPLIANCE VIEWS & DAILY SNAPSHOTS
-- -------------------------------------------------------------------------------------
-- Compliance rules used here (confirm with the architect / customer policy):
--   * A patch counts as remediated only when 'installed'. 'pending_reboot' is NOT
--     remediated - the vulnerable code is still running.
--   * Active patch_exceptions (device or any of its groups, not expired) are excluded.
--   * Device status: 'unknown' if the last patch scan is older than 7 days (stale data is
--     never shown as compliant), else 'non_compliant' if anything is past its SLA,
--     else 'compliant'.
-- These views are for drill-down and filtered queries. Fleet dashboards should read the
-- daily snapshot tables, not recompute over millions of rows on every page load.

CREATE VIEW device_patch_state_effective AS
SELECT
    s.device_id,
    s.patch_id,
    s.state,
    s.first_detected_missing_at,
    s.sla_due_at,
    s.installed_at,
    s.last_evaluated_at,
    pc.severity,
    pc.classification,
    pc.has_kev,
    EXISTS (
        SELECT 1
        FROM patch_exceptions pe
        WHERE pe.patch_id = s.patch_id
          AND pe.expires_at > now()
          AND (   pe.device_id = s.device_id
               OR pe.device_group_id = d.primary_group_id
               OR pe.device_group_id IN (SELECT m.group_id FROM device_group_membership m
                                          WHERE m.device_id = s.device_id))
    ) AS is_excepted,
    (s.state IN ('missing', 'failed', 'pending_reboot')
        AND s.sla_due_at IS NOT NULL AND s.sla_due_at < now()) AS is_overdue
FROM device_patch_state s
JOIN patch_catalog pc ON pc.id = s.patch_id
JOIN devices d ON d.id = s.device_id;

CREATE VIEW device_patch_compliance_current AS
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
        WHEN d.last_patch_scan_at IS NULL OR d.last_patch_scan_at < now() - INTERVAL '7 days' THEN 'unknown'
        WHEN count(e.patch_id) FILTER (WHERE e.is_overdue AND NOT e.is_excepted) > 0 THEN 'non_compliant'
        ELSE 'compliant'
    END AS compliance_status
FROM devices d
LEFT JOIN device_patch_state_effective e ON e.device_id = d.id
WHERE d.status = 'active'
GROUP BY d.id;

-- "Which patches are hurting us most?"
CREATE VIEW patch_compliance_by_patch AS
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
    min(e.first_detected_missing_at) FILTER (WHERE e.state IN ('missing', 'failed', 'pending_reboot')) AS oldest_missing_since
FROM patch_catalog pc
JOIN device_patch_state_effective e ON e.patch_id = pc.id
GROUP BY pc.id;

-- Point-in-time history. Auditors ask "what was compliance on date X" - that can't be
-- rebuilt from current-state tables later, so it is captured daily. (Hypertables in 0006.)
CREATE TABLE device_compliance_daily (
    time                    TIMESTAMPTZ NOT NULL,
    device_id               UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    compliance_status       TEXT NOT NULL CHECK (compliance_status IN ('compliant', 'non_compliant', 'unknown')),
    compliance_pct          NUMERIC(5,2),
    missing_count           INTEGER NOT NULL,
    missing_critical        INTEGER NOT NULL,
    missing_kev             INTEGER NOT NULL,
    overdue_count           INTEGER NOT NULL,
    pending_reboot_count    INTEGER NOT NULL,
    excepted_count          INTEGER NOT NULL
);
CREATE INDEX idx_dcd_device_time ON device_compliance_daily(device_id, time DESC);

CREATE TABLE group_compliance_daily (
    time                    TIMESTAMPTZ NOT NULL,
    device_group_id         UUID REFERENCES device_groups(id) ON DELETE CASCADE,  -- NULL = whole fleet
    total_devices           INTEGER NOT NULL,
    compliant_devices       INTEGER NOT NULL,
    non_compliant_devices   INTEGER NOT NULL,
    unknown_devices         INTEGER NOT NULL,
    avg_compliance_pct      NUMERIC(5,2),
    total_overdue_patches   INTEGER NOT NULL,
    total_missing_critical  INTEGER NOT NULL
);
CREATE INDEX idx_gcd_group_time ON group_compliance_daily(device_group_id, time DESC);

-- Nightly job calls this. Re-running for the same day replaces that day's rows (idempotent).
CREATE OR REPLACE FUNCTION snapshot_patch_compliance(p_time TIMESTAMPTZ DEFAULT date_trunc('day', now()))
RETURNS void AS $$
BEGIN
    DELETE FROM device_compliance_daily WHERE time = p_time;
    DELETE FROM group_compliance_daily  WHERE time = p_time;

    DROP TABLE IF EXISTS _snap;
    CREATE TEMP TABLE _snap ON COMMIT DROP AS
        SELECT * FROM device_patch_compliance_current;

    INSERT INTO device_compliance_daily
        (time, device_id, compliance_status, compliance_pct, missing_count, missing_critical,
         missing_kev, overdue_count, pending_reboot_count, excepted_count)
    SELECT p_time, device_id, compliance_status, compliance_pct, missing_count, missing_critical,
           missing_kev, overdue_count, pending_reboot_count, excepted_count
    FROM _snap;

    INSERT INTO group_compliance_daily
        (time, device_group_id, total_devices, compliant_devices, non_compliant_devices,
         unknown_devices, avg_compliance_pct, total_overdue_patches, total_missing_critical)
    SELECT p_time, m.group_id,
           count(*),
           count(*) FILTER (WHERE s.compliance_status = 'compliant'),
           count(*) FILTER (WHERE s.compliance_status = 'non_compliant'),
           count(*) FILTER (WHERE s.compliance_status = 'unknown'),
           round(avg(s.compliance_pct), 2),
           sum(s.overdue_count),
           sum(s.missing_critical)
    FROM _snap s
    JOIN device_group_membership m ON m.device_id = s.device_id
    GROUP BY m.group_id
    UNION ALL
    SELECT p_time, NULL,
           count(*),
           count(*) FILTER (WHERE compliance_status = 'compliant'),
           count(*) FILTER (WHERE compliance_status = 'non_compliant'),
           count(*) FILTER (WHERE compliance_status = 'unknown'),
           round(avg(compliance_pct), 2),
           coalesce(sum(overdue_count), 0),
           coalesce(sum(missing_critical), 0)
    FROM _snap;
END;
$$ LANGUAGE plpgsql;
