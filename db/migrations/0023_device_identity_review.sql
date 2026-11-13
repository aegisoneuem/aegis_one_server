-- =====================================================================================
-- 0023 device identity review (agent track: "TPM-Based Device Identity: Agent <-> Server
-- Split")
--
-- Enrollment reconciles a returning device by hardware signals. Identity matching only
-- reconciles device RECORDS; it never authorizes anything (that stays mTLS + signed
-- commands). Hostname is never an identity signal.
--   strong  tpm_ek, device_id      -> the existing record is reactivated automatically,
--                                     unless its agent is connected right now (a cloned
--                                     VM / vTPM, or a stolen identity): then conflict
--   weak    smbios_uuid, machine_id -> never merged automatically; the enrollment gets a
--                                     new record and an admin reviews the pair here
--
-- Confirming a pair moves the new record's agent onto the existing record (which keeps
-- its history) and marks the new record merged (devices.status = 'decommissioned',
-- merged_into_device_id set). audit_log is append-only, so old rows are linked, never
-- rewritten.
-- =====================================================================================

ALTER TABLE devices
    ADD COLUMN merged_into_device_id UUID REFERENCES devices(id);

CREATE TABLE device_merge_candidates (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    new_device_id      UUID NOT NULL REFERENCES devices(id),   -- record created by this enrollment
    existing_device_id UUID NOT NULL REFERENCES devices(id),   -- record it may be the same machine as
    matched_by         TEXT NOT NULL CHECK (matched_by IN
                           ('system_uuid', 'machine_guid', 'tpm_ek_conflict', 'device_id_conflict')),
    matched_value      TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'rejected')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at         TIMESTAMPTZ,
    decided_by         TEXT,             -- actor label, e.g. 'api_client:ops-console'
    decision_reason    TEXT,
    CHECK (new_device_id <> existing_device_id),
    UNIQUE (new_device_id, existing_device_id)
);
CREATE INDEX idx_device_merge_candidates_pending ON device_merge_candidates(created_at) WHERE status = 'pending';

INSERT INTO system_settings (key, value, description) VALUES
    ('device.stale_alert_days', '60', 'No heartbeat for this many days => stale device flagged prominently (never deleted)')
ON CONFLICT (key) DO NOTHING;
