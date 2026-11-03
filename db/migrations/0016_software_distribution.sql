-- 0016_software_distribution.sql
-- Software distribution to agents (the agent's software_deploy command).
--
-- A package is an installer uploaded to the server (POST
-- /internal/software/packages): the server computes its SHA-256 and keeps the
-- file under <content dir>/software/. A deployment sends one signed
-- software_deploy command per device; the agent fetches the file over
-- FetchContent (kind "package", id = package id), checks the SHA-256 pinned in
-- the command, installs, re-detects the product and reports an ActionStatus.

-- Fields the agent's SoftwareDeploySpec needs, beyond 0001's columns.
-- installer_type is the agent's own vocabulary; package_format (0001) stays the
-- coarse family ('msi' | 'exe' | 'script').
ALTER TABLE software_packages
    ADD COLUMN installer_type     TEXT CHECK (installer_type IN ('msi', 'exe', 'ps1', 'bat', 'cmd', 'python', 'vbs')),
    ADD COLUMN file_name          TEXT,      -- the name it was uploaded as, for display
    ADD COLUMN storage_name       TEXT,      -- relative to the content dir: software/<sha256><ext>
    ADD COLUMN product_code       TEXT,      -- MSI ProductCode {GUID}: detection + fileless uninstall
    ADD COLUMN uninstall_key      TEXT,      -- registry Uninstall subkey: detection + uninstall
    ADD COLUMN display_name       TEXT,      -- registry DisplayName: detection when there's no key
    ADD COLUMN success_exit_codes INTEGER[] NOT NULL DEFAULT '{}',   -- extra success codes beyond the agent's own 0, 3010, 1641
    ADD COLUMN timeout_seconds    INTEGER CHECK (timeout_seconds IS NULL OR timeout_seconds BETWEEN 1 AND 86400),
    ADD COLUMN require_signature  BOOLEAN NOT NULL DEFAULT false,    -- agent checks Authenticode before running
    ADD COLUMN created_by_api_client_id UUID REFERENCES api_clients(id),
    ADD COLUMN deleted_at         TIMESTAMPTZ;

-- Uninstall is 'remove' in 0001's CHECK; the API and the agent say 'uninstall'
-- and map it.
ALTER TABLE software_deployments
    ADD COLUMN name                     TEXT,
    ADD COLUMN created_by_api_client_id UUID REFERENCES api_clients(id),
    ADD COLUMN completed_at             TIMESTAMPTZ;

ALTER TABLE software_deployment_results
    ADD COLUMN package_id      UUID REFERENCES software_packages(id),
    ADD COLUMN command_id      UUID REFERENCES agent_commands(id),
    ADD COLUMN attempt_count   INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN exit_code       INTEGER,
    ADD COLUMN reboot_required BOOLEAN,
    ADD COLUMN outcome         TEXT,      -- agent's final phase: SUCCESS | NOT_APPLICABLE | FAILED
    ADD COLUMN updated_at      TIMESTAMPTZ NOT NULL DEFAULT now();

-- One running deployment of a package per device at a time.
CREATE UNIQUE INDEX uq_sdr_active_device_package ON software_deployment_results (device_id, package_id)
    WHERE status IN ('queued', 'in_progress');
CREATE INDEX idx_sdr_active ON software_deployment_results (updated_at)
    WHERE status IN ('queued', 'in_progress');
