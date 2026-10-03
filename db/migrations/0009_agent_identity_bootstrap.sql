-- 0009_agent_identity_bootstrap.sql
-- Supports TOFU (trust-on-first-use) identity for the agentcontrol/v1 contract,
-- which has no EnrollmentService: the server auto-creates devices/agents/
-- agent_certificates rows the first time it sees a new mTLS client cert
-- fingerprint, binding it to the agent-reported device_id string from then on
-- (internal/identity.Resolver). A real EnrollmentService-based flow would not
-- need agent_reported_id at all (identity comes purely from the cert), so this
-- column is specific to bootstrapping this simplified contract.

ALTER TABLE devices ADD COLUMN agent_reported_id TEXT UNIQUE;

ALTER TABLE agents
    DROP CONSTRAINT agents_install_method_check,
    ADD CONSTRAINT agents_install_method_check
        CHECK (install_method IN ('winrm_ssh_push', 'gpo_login_script', 'self_install_link',
                                   'third_party_rmm', 'offline_installer', 'unknown'));
