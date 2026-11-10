-- =====================================================================================
-- 0021 device lifecycle
--
-- A device's state is derived, not stored, except for retirement:
--   retired    devices.status = 'decommissioned' (set by POST /internal/devices/retire)
--   online     last heartbeat within agent.offline_after_minutes (0007, default 15)
--   offline    last heartbeat within device.stale_after_days
--   stale      no heartbeat for device.stale_after_days (default 30), or never
--
-- Retiring revokes the device's agent and certificates (the agent is refused at its
-- next connect), keeps all history, and frees the license seat. A retired device comes
-- back only by enrolling again with a token (enrollment checks the license again).
-- =====================================================================================

ALTER TABLE devices
    ADD COLUMN retired_at     TIMESTAMPTZ,
    ADD COLUMN retired_reason TEXT,
    ADD COLUMN retired_by     TEXT;      -- actor label, e.g. 'api_client:ops-console'

INSERT INTO system_settings (key, value, description) VALUES
    ('device.stale_after_days', '30', 'No heartbeat for this many days => device shown as stale')
ON CONFLICT (key) DO NOTHING;
