-- 0012_enrollment.sql
-- Device identity for the agent's Enroll RPC (agent team's
-- server-identity-reconciliation-contract.md). Enrollment reconciles a request to
-- one logical device by hardware signals, strongest first:
--   tpm_ek  >  device_id (devices.agent_reported_id)  >  smbios_uuid  >  machine_id
-- smbios_uuid and machine_id, and their indexes, already exist (0005).

-- TPM Endorsement Key fingerprint as sent by the agent ("tpm:<sha256 hex>").
-- Firmware-bound and clone-proof, so it is unique per physical machine.
ALTER TABLE devices ADD COLUMN tpm_ek TEXT;
CREATE UNIQUE INDEX uq_devices_tpm_ek ON devices(tpm_ek) WHERE tpm_ek IS NOT NULL;

-- Console-facing id (BigFix ComputerID style): random 10-digit, assigned once per
-- device and never reused. Random rather than sequential so it doesn't leak how
-- many devices are enrolled.
ALTER TABLE devices ADD COLUMN computer_id BIGINT UNIQUE
    CHECK (computer_id BETWEEN 1000000000 AND 9999999999);
