-- 0019_software_distribution_v2.sql
-- Software distribution v2, matching the agent's software_deploy_v2 /
-- _bundle / _workflow / _detect commands (agent zip 4):
--   * bundles: one ZIP with an aegis-package.json manifest, run from an entry
--     point or a command
--   * before / after / rollback steps (bundles only)
--   * advanced detection rules (file / file version / registry, ALL or ANY)
--   * public parameters, AC-power gate, script-content audit flag
--   * dependencies: install other packages first (orchestrated by the server)
--   * run-as (logged-in user / specified account) and secure parameters per
--     deployment. The password and secret values are NEVER stored: the server
--     keeps them in memory only until the deployment's commands are sent.

ALTER TABLE software_packages DROP CONSTRAINT software_packages_package_format_check;
ALTER TABLE software_packages ADD CONSTRAINT software_packages_package_format_check
    CHECK (package_format IN ('msi', 'exe', 'dmg', 'pkg', 'deb', 'rpm', 'script', 'bundle', 'driver', 'msix', 'command'));

ALTER TABLE software_packages DROP CONSTRAINT software_packages_installer_type_check;
ALTER TABLE software_packages ADD CONSTRAINT software_packages_installer_type_check
    CHECK (installer_type IN ('msi', 'exe', 'ps1', 'bat', 'cmd', 'python', 'vbs', 'inf', 'msix', 'command'));

ALTER TABLE software_packages
    ADD COLUMN is_bundle              BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN bundle_entry_point     TEXT,          -- manifested path run as installer_type
    ADD COLUMN bundle_command         TEXT,          -- or: command line run in the extracted folder
    ADD COLUMN bundle_destination     TEXT,          -- '' = agent-managed temp folder
    ADD COLUMN bundle_cleanup         TEXT CHECK (bundle_cleanup IS NULL OR bundle_cleanup IN ('always', 'retain')),
    ADD COLUMN bundle_files           INTEGER,
    ADD COLUMN steps                  JSONB,         -- {"before":[...],"after":[...],"rollback":[...]}
    ADD COLUMN detection              JSONB,         -- {"mode":"all|any","rules":[...]}
    ADD COLUMN parameters             JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN requires               UUID[] NOT NULL DEFAULT '{}',   -- packages installed first
    ADD COLUMN require_ac_power       BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN capture_script_content BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT software_packages_bundle_shape CHECK (
        NOT is_bundle OR ((bundle_entry_point IS NULL) <> (bundle_command IS NULL)));

-- Per deployment: who the installer runs as, and the transfer rate cap.
-- has_secrets marks a deployment whose password / secure parameters live only
-- in server memory.
ALTER TABLE software_deployments
    ADD COLUMN execution_mode     TEXT NOT NULL DEFAULT 'system'
                                      CHECK (execution_mode IN ('system', 'logged_in_user', 'specified_account')),
    ADD COLUMN session_id         INTEGER CHECK (session_id IS NULL OR session_id >= 0),
    ADD COLUMN run_as_username    TEXT,
    ADD COLUMN run_as_domain      TEXT,
    ADD COLUMN detection_scope    TEXT CHECK (detection_scope IS NULL OR detection_scope IN ('machine', 'user')),
    ADD COLUMN has_secrets        BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN secure_param_names TEXT[] NOT NULL DEFAULT '{}',      -- names only, never values
    ADD COLUMN max_fetch_bytes_per_second BIGINT CHECK (max_fetch_bytes_per_second IS NULL OR max_fetch_bytes_per_second > 0);

-- A deployment now holds one result per (device, package): the package and
-- the dependencies installed before it, in plan_order.
ALTER TABLE software_deployment_results DROP CONSTRAINT software_deployment_results_deployment_id_device_id_key;
ALTER TABLE software_deployment_results
    ADD COLUMN plan_order        INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN command_type      TEXT,
    ADD COLUMN package_directory TEXT,
    ADD COLUMN package_cleanup   TEXT,
    ADD CONSTRAINT software_deployment_results_dep_dev_pkg UNIQUE (deployment_id, device_id, package_id);
