-- =====================================================================================
-- 0026 DEX extended telemetry (agent 2026-11-15: DexTelemetry fields 11-35)
--
-- Same 5-minute window as cpu_pct / ram_pct (0024), one row per report:
--   disk     PhysicalDisk(_Total) queue length, transfers/s, latency (ms)
--   network  ICMP round trip (ms) and loss (%) to the default gateway or a configured
--            target
--   battery  present, on AC, charge (%)
--   wifi     present, connected, signal quality (0-100)
-- NULL means not reported: an older agent, or the agent could not read it.
-- wifi_ssid / net_target are only stored when AEGIS_DEX_NETWORK_NAMES=on (they can show
-- where the user is).
-- Nullable columns only: allowed on a hypertable with compression enabled.
-- =====================================================================================

ALTER TABLE device_dex_metrics
    ADD COLUMN disk_queue_avg      REAL,
    ADD COLUMN disk_queue_min      REAL,
    ADD COLUMN disk_queue_max      REAL,
    ADD COLUMN disk_iops_avg       REAL,
    ADD COLUMN disk_iops_min       REAL,
    ADD COLUMN disk_iops_max       REAL,
    ADD COLUMN disk_latency_ms_avg REAL,
    ADD COLUMN disk_latency_ms_min REAL,
    ADD COLUMN disk_latency_ms_max REAL,
    ADD COLUMN net_rtt_ms_avg      REAL,
    ADD COLUMN net_rtt_ms_min      REAL,
    ADD COLUMN net_rtt_ms_max      REAL,
    ADD COLUMN net_loss_pct        REAL,
    ADD COLUMN net_target          TEXT,
    ADD COLUMN battery_present     BOOLEAN,
    ADD COLUMN battery_ac_online   BOOLEAN,
    ADD COLUMN battery_pct_avg     REAL,
    ADD COLUMN battery_pct_min     REAL,
    ADD COLUMN battery_pct_max     REAL,
    ADD COLUMN wifi_present        BOOLEAN,
    ADD COLUMN wifi_connected      BOOLEAN,
    ADD COLUMN wifi_signal_pct_avg REAL,
    ADD COLUMN wifi_signal_pct_min REAL,
    ADD COLUMN wifi_signal_pct_max REAL,
    ADD COLUMN wifi_ssid           TEXT;
