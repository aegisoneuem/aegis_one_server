-- 0017_agent_inventory_audit.sql
-- What the agent (zip 4, proto commits 2240a16 / e1d3d6b / 88b3709) now sends
-- that had nowhere to go:
--   Heartbeat / EnrollRequest: schema_version, agent_capabilities, device_type
--   DeviceStateReport:         installed_kbs (CBS + QFE + WUA local), installed_apps
--   FullInventoryReport:       hardware (CPU, memory, BIOS, system vendor/model,
--                              disks, NICs), installed_apps, drivers, appx packages
--   AuditEvent:                command_received / command_rejected /
--                              command_completed, enrollment and cert events
--
-- Existing tables are reused where they fit (software_inventory, device_disks,
-- device_network_interfaces, device_ip_addresses, devices.bios_*, manufacturer,
-- model, serial_tag, cpu_model, ram_gb).

ALTER TABLE agents
    ADD COLUMN schema_version     TEXT,
    ADD COLUMN agent_capabilities TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN device_type        TEXT;

ALTER TABLE devices
    ADD COLUMN cpu_vendor          TEXT,
    ADD COLUMN cpu_physical_cores  INTEGER,
    ADD COLUMN cpu_logical_cores   INTEGER,
    ADD COLUMN chassis_type        TEXT,
    ADD COLUMN virtualization      TEXT,      -- 'vmware', 'hyperv', ... ; empty = physical/unknown
    ADD COLUMN installed_kbs_at    TIMESTAMPTZ;

-- The device's installed update set, replaced on every DeviceStateReport that
-- carries one. Input to the server-side diff (docs/server-spec-patch-detection.md
-- in the agent repo): missing = applicable - installed.
CREATE TABLE device_installed_kbs (
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kb          TEXT NOT NULL CHECK (kb ~ '^KB[0-9]{4,8}$'),
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, kb)
);
CREATE INDEX idx_dik_kb ON device_installed_kbs (kb);

-- Fields the agent's InstalledApp carries beyond 0001's columns. app_version is
-- stored as '' (not NULL) when unknown so UNIQUE (device_id, app_name,
-- app_version) also covers version-less apps.
ALTER TABLE software_inventory
    ADD COLUMN uninstall_key     TEXT,
    ADD COLUMN hive              TEXT,
    ADD COLUMN estimated_size_kb BIGINT,
    ADD COLUMN uninstall_string  TEXT;

-- Signed PnP drivers (Win32_PnPSignedDriver), replaced per full inventory. The
-- OEM driver catalog matches on hardware_id + provider_name + version/date.
CREATE TABLE device_drivers (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id      UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    device_name    TEXT NOT NULL,
    device_class   TEXT,
    driver_version TEXT NOT NULL,
    driver_date    DATE,
    provider_name  TEXT,
    hardware_id    TEXT,
    inf_name       TEXT,
    manufacturer   TEXT,
    is_signed      BOOLEAN NOT NULL DEFAULT false,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_dd_device ON device_drivers (device_id);
CREATE INDEX idx_dd_hardware ON device_drivers (hardware_id, provider_name);

-- MSIX / Store packages, replaced per full inventory.
CREATE TABLE device_appx_packages (
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    package_full_name   TEXT NOT NULL,
    package_family_name TEXT,
    name                TEXT,
    display_name        TEXT,
    version             TEXT,
    architecture        TEXT,
    publisher_id        TEXT,
    install_location    TEXT,
    origin              TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, package_full_name)
);
CREATE INDEX idx_dap_family ON device_appx_packages (package_family_name);

-- The agent's audit stream. The agent dropped its local hash chain ("Option C"),
-- so this table is the authoritative record: append-only like audit_log.
-- command_received and command_completed share command_id; join them for one
-- dispatch -> outcome record. ts is the agent's clock (unix millis);
-- received_at is ours. No foreign keys on purpose: the trail must outlive a
-- deleted device, and a cascading delete would hit the no-delete trigger.
CREATE TABLE agent_audit_events (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id    UUID NOT NULL,       -- devices.id at the time
    agent_id     UUID NOT NULL,       -- agents.id at the time
    ts           TIMESTAMPTZ NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type   TEXT NOT NULL,       -- command_received | command_rejected | command_completed | enrollment_* | cert_renewed | audit_degraded
    command_id   TEXT,                -- as the agent sent it (not always one of ours)
    command_type TEXT,
    actor        TEXT,
    source       TEXT,
    issued_at    TIMESTAMPTZ,
    signature_ok BOOLEAN NOT NULL DEFAULT false,
    decision     TEXT,                -- accepted | rejected | succeeded | failed | skipped | degraded
    reason       TEXT,
    details      TEXT
);
-- A reconnecting agent may resend buffered events; the same event twice is one row.
CREATE UNIQUE INDEX uq_aae_event ON agent_audit_events (device_id, ts, event_type, coalesce(command_id, ''));
CREATE INDEX idx_aae_device_ts ON agent_audit_events (device_id, ts DESC);
CREATE INDEX idx_aae_command ON agent_audit_events (command_id) WHERE command_id IS NOT NULL;

CREATE OR REPLACE FUNCTION reject_append_only_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not permitted', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_agent_audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON agent_audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
CREATE TRIGGER trg_agent_audit_events_no_truncate
    BEFORE TRUNCATE ON agent_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_mutation();
