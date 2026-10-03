-- =====================================================================================
-- AEGIS ONE - Database Schema v2
-- File 2 of 4: 0002_timescale.sql
-- Needs the TimescaleDB extension (the timescale/timescaledb Docker image has it).
-- On plain PostgreSQL, SKIP this file: everything in 0001 still works, dashboards just
-- read the raw tables instead of rollups.
-- =====================================================================================

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Convert the three time-series tables from 0001 into hypertables.
-- migrate_data => TRUE makes this safe even if test rows were already inserted.
SELECT create_hypertable('agent_heartbeats', 'time', if_not_exists => TRUE, migrate_data => TRUE);
SELECT create_hypertable('device_dex_metrics', 'time', if_not_exists => TRUE, migrate_data => TRUE);
SELECT create_hypertable('vulnerability_exposure_snapshots', 'time', if_not_exists => TRUE, migrate_data => TRUE);


-- ---- Heartbeats: compress after 7 days, drop raw rows after 1 year -------------------
ALTER TABLE agent_heartbeats SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id'
);
SELECT add_compression_policy('agent_heartbeats', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_retention_policy('agent_heartbeats', INTERVAL '365 days', if_not_exists => TRUE);

-- Hourly rollup so dashboards never scan raw heartbeats (ADR 10.3).
CREATE MATERIALIZED VIEW agent_heartbeats_hourly
WITH (timescaledb.continuous) AS
SELECT
    device_id,
    time_bucket('1 hour', time) AS bucket,
    avg(cpu_pct)        AS avg_cpu_pct,
    avg(ram_pct)        AS avg_ram_pct,
    min(disk_free_gb)   AS min_disk_free_gb,
    sum(CASE WHEN connection_state = 'disconnected' THEN 1 ELSE 0 END) AS disconnect_events
FROM agent_heartbeats
GROUP BY device_id, bucket
WITH NO DATA;

SELECT add_continuous_aggregate_policy('agent_heartbeats_hourly',
    start_offset      => INTERVAL '3 hours',
    end_offset        => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists     => TRUE);


-- ---- DEX: compress after 90 days (ADR: "data older than 90 days is compressed") -----
ALTER TABLE device_dex_metrics SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id'
);
SELECT add_compression_policy('device_dex_metrics', INTERVAL '90 days', if_not_exists => TRUE);

CREATE MATERIALIZED VIEW device_dex_daily
WITH (timescaledb.continuous) AS
SELECT
    device_id,
    time_bucket('1 day', time) AS bucket,
    avg(boot_time_seconds)  AS avg_boot_time_seconds,
    sum(app_crash_count)    AS total_crashes,
    avg(cpu_pct)            AS avg_cpu_pct,
    avg(ram_pct)            AS avg_ram_pct,
    avg(experience_score)   AS avg_experience_score
FROM device_dex_metrics
GROUP BY device_id, bucket
WITH NO DATA;

SELECT add_continuous_aggregate_policy('device_dex_daily',
    start_offset      => INTERVAL '3 days',
    end_offset        => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day',
    if_not_exists     => TRUE);

-- DEX correlated with recent deployments (RFP DEX req #4).
CREATE VIEW device_dex_with_recent_deployments AS
SELECT
    d.device_id,
    d.bucket,
    d.avg_experience_score,
    d.total_crashes,
    (SELECT max(pdr.completed_at) FROM patch_deployment_results pdr
      WHERE pdr.device_id = d.device_id AND pdr.status = 'succeeded'
        AND pdr.completed_at BETWEEN d.bucket - INTERVAL '1 day' AND d.bucket) AS last_patch_applied_at,
    (SELECT max(sdr.completed_at) FROM software_deployment_results sdr
      WHERE sdr.device_id = d.device_id AND sdr.status = 'succeeded'
        AND sdr.completed_at BETWEEN d.bucket - INTERVAL '1 day' AND d.bucket) AS last_software_applied_at
FROM device_dex_daily d;
