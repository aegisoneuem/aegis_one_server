-- 0020_remote_operations.sql
-- Remote operations on endpoints (agent zip 4): collect_file, run_command,
-- file_operation and open_shell. Every one is a signed agent_commands row
-- (audited) first; these tables hold what comes back.

-- Files an agent streamed up with UploadContent (collect_file, run_command
-- upload_as, file_operation pack). Stored under <content dir>/uploads/.
-- Only accepted for an open command of that agent that may upload.
CREATE TABLE agent_uploads (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    agent_id     UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    command_id   UUID NOT NULL REFERENCES agent_commands(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,          -- file name the agent sent (sanitised)
    stored_name  TEXT NOT NULL UNIQUE,   -- relative to the content dir
    size_bytes   BIGINT NOT NULL,
    sha256       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_uploads_command ON agent_uploads (command_id);

-- Copy / move files from one endpoint to others: pack on the source, upload
-- to the server, unpack on each destination (it fetches the archive with
-- FetchContent kind "nsh-file", by a random content_id bound to that
-- destination and the archive's SHA-256), then for a move delete the source
-- files once every destination has them.
CREATE TABLE file_transfers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source_path       TEXT NOT NULL,
    recursive         BOOLEAN NOT NULL DEFAULT false,
    destination       TEXT NOT NULL,
    overwrite         BOOLEAN NOT NULL DEFAULT false,
    is_move           BOOLEAN NOT NULL DEFAULT false,
    status            TEXT NOT NULL DEFAULT 'packing'
                          CHECK (status IN ('packing', 'distributing', 'removing_source', 'succeeded', 'failed')),
    pack_command_id   UUID REFERENCES agent_commands(id),
    upload_id         UUID REFERENCES agent_uploads(id),
    archive_sha256    TEXT,
    entries           JSONB,             -- the pack result's file list, sent to every destination
    remove_command_id UUID REFERENCES agent_commands(id),
    error_message     TEXT,
    created_by_api_client_id UUID REFERENCES api_clients(id),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at      TIMESTAMPTZ
);
CREATE INDEX idx_file_transfers_active ON file_transfers (updated_at) WHERE status NOT IN ('succeeded', 'failed');

CREATE TABLE file_transfer_targets (
    transfer_id   UUID NOT NULL REFERENCES file_transfers(id) ON DELETE CASCADE,
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status        TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'in_progress', 'succeeded', 'failed')),
    content_id    TEXT UNIQUE,           -- random, single destination; what FetchContent "nsh-file" asks for
    command_id    UUID REFERENCES agent_commands(id),
    error_message TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (transfer_id, device_id)
);

-- Interactive shells (open_shell + the ShellSession stream). The operator's
-- input and the shell's output are recorded to a transcript file under
-- <content dir>/shell/.
CREATE TABLE shell_sessions (
    id              TEXT PRIMARY KEY,        -- random session id (in the signed open_shell)
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    command_id      UUID REFERENCES agent_commands(id),
    created_by_api_client_id UUID REFERENCES api_clients(id),
    status          TEXT NOT NULL DEFAULT 'opening' CHECK (status IN ('opening', 'active', 'closed', 'failed')),
    ttl_seconds     INTEGER NOT NULL,
    idle_timeout_seconds INTEGER NOT NULL,
    max_duration_seconds INTEGER NOT NULL,
    transcript_name TEXT,
    bytes_in        BIGINT NOT NULL DEFAULT 0,
    bytes_out       BIGINT NOT NULL DEFAULT 0,
    exit_code       INTEGER,
    close_reason    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    opened_at       TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ
);
CREATE INDEX idx_shell_sessions_device ON shell_sessions (device_id, created_at DESC);
