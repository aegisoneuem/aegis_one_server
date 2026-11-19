-- =====================================================================================
-- 0031 agent 2026-11-19 (proto d1fed59): battery health, per-crash detail, installed AV
--
-- DexTelemetry 36/37   battery_health_pct (full-charge / designed capacity x 100,
--                      100 = like new) and battery_cycle_count. The agent sends 0 for
--                      unknown; the server stores NULL.
-- AppFault 4-6         module, exception code and time of the most recent crash of
--                      each faulting app. Older agents leave them empty -> NULL.
-- FullInventoryReport  antivirus_products: what Windows Security Center lists.
--     11               One row per product; the list replaces the device's rows when it
--                      is non-empty. An empty list means "Server SKU / no Security
--                      Center" per the agent team, so it leaves the rows alone like
--                      every other inventory section. The headline (the enabled
--                      product, real-time on/off) is mirrored into
--                      device_security_posture, which gets its first writer here.
-- Nullable columns only on the hypertable (compression is enabled on it, see 0026).
-- Run 0004 again afterwards (cmd/migrate does).
-- =====================================================================================

ALTER TABLE device_dex_metrics
    ADD COLUMN battery_health_pct  REAL,
    ADD COLUMN battery_cycle_count INTEGER;

ALTER TABLE device_app_faults
    ADD COLUMN last_module    TEXT,
    ADD COLUMN last_exception TEXT,
    ADD COLUMN last_crash_at  TIMESTAMPTZ;

CREATE TABLE device_antivirus_products (
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,              -- Security Center displayName
    enabled       BOOLEAN NOT NULL,           -- real-time protection on
    up_to_date    BOOLEAN NOT NULL,           -- signatures current
    product_state BIGINT NOT NULL,            -- raw SecurityCenter2 productState bitmask
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, name)
);
CREATE INDEX idx_device_antivirus_name ON device_antivirus_products (name);
