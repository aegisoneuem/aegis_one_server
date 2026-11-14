-- =====================================================================================
-- 0025 agent policy (agent 2026-11-09..12: signed set_policy command)
--
-- One policy for the whole fleet (Sam, 2026-11-14). The document is the JSON payload of
-- an Ed25519-signed set_policy command; the agent keeps it, re-verifies it at startup
-- and refuses an older one (anti-rollback on issued_at). So:
--   agent_policies      every published version, never edited. The newest issued_at is
--                       the current policy. wire = the exact bytes that are signed and
--                       sent, so every push of a version is byte-identical.
--   agent_policy_state  per agent: which version was last pushed and what the agent
--                       said. Drives the push on connect, and a re-push when the agent
--                       reports that its stored policy was tampered with (it then runs
--                       in fail-closed safe mode until the server re-asserts it).
-- Publishing needs the new permission agent.policy (admin only: no role is seeded
-- with it).
-- =====================================================================================

CREATE TABLE agent_policies (
    id                       UUID PRIMARY KEY,               -- = policy_id in the document
    issued_at                BIGINT NOT NULL UNIQUE,         -- unix seconds, strictly increasing
    document                 JSONB NOT NULL,                 -- for display / API
    wire                     BYTEA NOT NULL,                 -- exact signed payload
    note                     TEXT,
    created_by_api_client_id UUID REFERENCES api_clients(id),
    created_by_label         TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE agent_policy_state (
    agent_id      UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    policy_id     UUID NOT NULL REFERENCES agent_policies(id),
    issued_at     BIGINT NOT NULL,
    command_id    UUID,
    -- pending  pushed (or about to be), no answer yet: pushed again on the next connect
    -- applied  agent applied it, or already had it (NOT_APPLICABLE)
    -- failed   agent refused it: retried only after the agent version changes
    -- tampered agent reported its stored policy deleted / modified / rolled back
    status        TEXT NOT NULL CHECK (status IN ('pending', 'applied', 'failed', 'tampered')),
    reason        TEXT,
    agent_version TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_policy_state_status ON agent_policy_state (status);
