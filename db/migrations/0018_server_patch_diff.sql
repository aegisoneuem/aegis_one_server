-- 0018_server_patch_diff.sql
-- The server now computes what a device is missing (agent repo:
-- docs/server-spec-patch-detection.md). The agent sends its build + UBR,
-- architecture and installed KBs (DeviceStateReport, 0017); the wsusscn2.cab
-- stays on the server. This replaces 0014's "the agent's scan report is the
-- source of truth": the endpoint cab scan is now optional (air-gapped /
-- on-demand) and its rows are kept only while fresh.
--
-- What the diff decides today: the Windows cumulative update. The device's
-- build + UBR is authoritative - the newest KB MSRC lists for its (client|
-- server, architecture, build) family is missing if its UBR is above the
-- device's, else installed (os_fixed_builds, 0015). Standalone / .NET / Office
-- applicability needs product signals the agent doesn't send yet, so those come
-- only from an optional agent scan.

-- Rows written by the server-side diff.
ALTER TABLE device_patch_state DROP CONSTRAINT device_patch_state_detection_source_check;
ALTER TABLE device_patch_state ADD CONSTRAINT device_patch_state_detection_source_check
    CHECK (detection_source IN ('agent_wua', 'agent_package_manager', 'agent_rule', 'agentless_scan', 'server_diff'));

-- The install feedback loop: the agent answered NOT_APPLICABLE to an
-- install_patch for this patch ("already installed" or "doesn't apply"), so
-- the diff stops offering it - but only while the device is still on the
-- build it reported then; a new build is evaluated afresh.
CREATE TABLE device_patch_not_applicable (
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    patch_id    UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    full_build  TEXT NOT NULL,        -- '26100.4652' when the agent said it
    command_id  UUID REFERENCES agent_commands(id) ON DELETE SET NULL,
    reason      TEXT,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, patch_id)
);

-- Which catalog the device was last diffed against, so "missing as of
-- catalog X" can be explained. The key is a short hash of the fixed-build
-- index (changes whenever MSRC brings a newer cumulative KB).
ALTER TABLE devices
    ADD COLUMN patch_diff_catalog TEXT,
    ADD COLUMN patch_diff_at      TIMESTAMPTZ;
