-- =====================================================================================
-- 0024 DEX ingest (agent 2026-11-12: DexTelemetry, FullInventoryReport.identity /
-- dex_health)
--
--   DexTelemetry      every 5 min per agent: CPU / memory avg, min, max over the window.
--                     One row in the device_dex_metrics hypertable (cpu_pct / ram_pct
--                     hold the averages, so device_dex_daily keeps working). Written
--                     in batches with COPY, never one INSERT per message.
--   dex_health        stability counts over the agent's last window_days (unexpected
--                     shutdowns, bugchecks, dirty power, app crashes / hangs, boot
--                     duration). The counts are a rolling window, not deltas, so they
--                     are kept as the latest snapshot per device, not summed.
--   identity          logged-on user, domain, domain-joined, boot time -> the existing
--                     devices columns (last_logged_on_user, domain_name,
--                     is_domain_joined, last_boot_at).
-- =====================================================================================

-- Nullable columns only: allowed on a hypertable with compression enabled.
ALTER TABLE device_dex_metrics
    ADD COLUMN cpu_min_pct    REAL,
    ADD COLUMN cpu_max_pct    REAL,
    ADD COLUMN ram_min_pct    REAL,
    ADD COLUMN ram_max_pct    REAL,
    ADD COLUMN window_seconds INTEGER,
    ADD COLUMN sample_count   INTEGER;

CREATE TABLE device_dex_health (
    device_id            UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    window_days          INTEGER NOT NULL,
    unexpected_shutdowns INTEGER NOT NULL DEFAULT 0,
    bugchecks            INTEGER NOT NULL DEFAULT 0,
    dirty_power_events   INTEGER NOT NULL DEFAULT 0,
    app_crashes          INTEGER NOT NULL DEFAULT 0,
    app_hangs            INTEGER NOT NULL DEFAULT 0,
    boot_duration_ms     BIGINT,                 -- NULL when the agent could not read it
    collected_at         TIMESTAMPTZ NOT NULL,   -- agent clock
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-app crash / hang counts in the same window; replaced on every report.
CREATE TABLE device_app_faults (
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    app_name   TEXT NOT NULL,
    crashes    INTEGER NOT NULL DEFAULT 0,
    hangs      INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, app_name)
);
CREATE INDEX idx_device_app_faults_app ON device_app_faults (app_name);
