-- =====================================================================================
-- 0027 Patch operations: gaps against the agent (2026-11-15 audit)
--
--   agent_commands.last_status_at   when the agent last reported on a command. A push
--                                   step now times out after 6h of SILENCE, not 6h
--                                   after dispatch, and a step the agent deferred to
--                                   its maintenance window waits much longer.
--   patch_deployments               reboot after install (if_required | always), the
--                                   reboot delay/message, and stage-only pushes
--                                   (pre-cache ahead of a window, no install).
--   patch_deployment_results        step 'rebooting', the reboot command and outcome.
--   devices                         KBs waiting for a reboot (DeviceStateReport), the
--                                   agent's last "patch cache full" report, the last
--                                   optional cab scan, and HardwareInventory fields
--                                   15-21 that were dropped until now.
--   device_disks                    volume label and drive type.
--   device_patch_scan_runs          every cab scan the agent reports ("scan-<unix>"),
--                                   failed ones included (they were dropped).
--   patch_catalog                   download size and description from the agent's
--                                   cab scan (agent-reported KBs only).
-- =====================================================================================

ALTER TABLE agent_commands ADD COLUMN last_status_at TIMESTAMPTZ;

-- Reboot after install. Existing values stay valid; new pushes use no_reboot,
-- if_required or always.
ALTER TABLE patch_deployments DROP CONSTRAINT patch_deployments_reboot_behavior_check;
ALTER TABLE patch_deployments ADD CONSTRAINT patch_deployments_reboot_behavior_check
    CHECK (reboot_behavior IN ('immediate', 'user_deferred', 'no_reboot', 'if_required', 'always'));
ALTER TABLE patch_deployments
    ADD COLUMN reboot_delay_seconds INTEGER CHECK (reboot_delay_seconds BETWEEN 0 AND 86400),
    ADD COLUMN reboot_message       TEXT CHECK (length(reboot_message) <= 400),
    ADD COLUMN stage_only           BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE patch_deployment_results DROP CONSTRAINT patch_deployment_results_step_check;
ALTER TABLE patch_deployment_results ADD CONSTRAINT patch_deployment_results_step_check
    CHECK (step IN ('downloading', 'staging', 'installing', 'rebooting'));
ALTER TABLE patch_deployment_results
    ADD COLUMN reboot_command_id UUID REFERENCES agent_commands(id),
    ADD COLUMN reboot_outcome    TEXT;

ALTER TABLE devices
    ADD COLUMN pending_reboot_kbs       TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN patch_cache_full_at      TIMESTAMPTZ,
    ADD COLUMN patch_cache_needed_bytes BIGINT,
    ADD COLUMN patch_cache_cap_bytes    BIGINT,
    ADD COLUMN patch_cache_in_use_bytes BIGINT,
    ADD COLUMN last_cab_scan_at         TIMESTAMPTZ,
    ADD COLUMN last_cab_scan_status     TEXT CHECK (last_cab_scan_status IN ('succeeded', 'failed')),
    ADD COLUMN last_cab_scan_reason     TEXT,
    ADD COLUMN cpu_mhz                  INTEGER,
    ADD COLUMN cpu_threads_per_core     INTEGER,
    ADD COLUMN cpu_architecture         TEXT,
    ADD COLUMN os_service_pack          TEXT;

ALTER TABLE device_disks
    ADD COLUMN volume_label TEXT,
    ADD COLUMN drive_type   TEXT;

-- One row per cab scan the agent reports. Kept 90 days (pruned on insert).
CREATE TABLE device_patch_scan_runs (
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    action_id   TEXT NOT NULL,          -- the agent's "scan-<unix>"
    status      TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    reason      TEXT,
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, action_id)
);
CREATE INDEX idx_device_patch_scan_runs_recent ON device_patch_scan_runs(device_id, received_at DESC);

ALTER TABLE patch_catalog
    ADD COLUMN download_size_mb NUMERIC(12,2),
    ADD COLUMN description      TEXT;
