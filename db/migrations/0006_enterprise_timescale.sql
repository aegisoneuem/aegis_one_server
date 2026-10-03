-- =====================================================================================
-- AEGIS ONE - Database Schema v3
-- File 6: 0006_enterprise_timescale.sql   (needs TimescaleDB; run after 0005)
-- Uses the same TimescaleDB function names as 0002 - if 0002 ran cleanly on your server,
-- this one will too. Skip on plain PostgreSQL; call snapshot_patch_compliance() from the
-- app's own scheduler instead.
-- After this file, re-run 0004_db_roles.sql once so the new tables/views get the same grants.
-- =====================================================================================

SELECT create_hypertable('device_compliance_daily', 'time', if_not_exists => TRUE, migrate_data => TRUE);
SELECT create_hypertable('group_compliance_daily',  'time', if_not_exists => TRUE, migrate_data => TRUE);

-- Compliance history is audit evidence: compress, but do NOT add a retention policy here.
-- How long to keep it is a customer/regulatory decision - set it deliberately per deployment.
ALTER TABLE device_compliance_daily SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id'
);
SELECT add_compression_policy('device_compliance_daily', INTERVAL '30 days', if_not_exists => TRUE);

-- Nightly snapshot via TimescaleDB's built-in job scheduler (no cron needed).
CREATE OR REPLACE PROCEDURE job_snapshot_patch_compliance(job_id INTEGER, config JSONB)
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM snapshot_patch_compliance();
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM timescaledb_information.jobs
                   WHERE proc_name = 'job_snapshot_patch_compliance') THEN
        PERFORM add_job('job_snapshot_patch_compliance', INTERVAL '1 day',
                        initial_start => date_trunc('day', now()) + INTERVAL '1 day 30 minutes');
    END IF;
END
$$;
