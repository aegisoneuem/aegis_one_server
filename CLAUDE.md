# Aegis One - project context for Claude Code

Aegis One is an enterprise UEM product: patch management, software distribution,
built-in vulnerability assessment (VA), hardware/software inventory and DEX-lite, for
up to 50,000-100,000 endpoints per on-prem deployment (BFSI / government focus, India).
One agent, one console. This repo is the **application/management server** plus the
agent<->server contract.

## Working with Sam (the owner)
- Explain in simple Hinglish; keep it short and practical. Copy-ready commands.
- Sam is not writing every line himself - he reviews. Say what changed and why.
- Before anything destructive (DROP, DELETE, overwriting files, force-push): show what
  will happen and ask first.

## Locked architecture decisions (from ADR v7 / Agent Spec v5)
- Backend: **Go**. Console: React + TypeScript SPA served by the same binary.
- DB: **PostgreSQL 17 + TimescaleDB** (dev server runs TimescaleDB 2.30.1).
- Agent<->server: **gRPC over mTLS**, one long-lived bidirectional stream, agent-initiated
  (endpoint never listens). Protobuf, not JSON.
- Every server->agent command/config/key-set/manifest is **Ed25519-signed**.
- Content integrity: SHA-256 + signed manifests, fail-closed at every hop.
- Packaging: application server ships as **one Docker image**; Postgres stays in its own
  container/volume (never inside the app image). Same image runs via docker-compose or K3s.
- Internal event bus: in-process (Go channels) for v1; keep module boundaries clean so NATS
  can replace it later. (Open item - confirm with architect.)
- Secrets never in code, config files or Git. Vault (enterprise) / encrypted local store (v1).

## Repo layout
```
buf.yaml, buf.gen.yaml        # buf v2 config (module path: proto)
proto/aegis/agent/v1/*.proto  # the contract - source of truth for agent<->server messages
gen/                          # generated Go code (buf generate) - do not hand-edit
db/migrations/0001..0007.sql  # PostgreSQL schema, apply in order
go.mod                        # module "aegis-one" (matches go_package in the protos)
```

## Database (db/migrations) - already applied on the dev DB
| File | Contents |
|---|---|
| 0001_core_schema | RBAC, users, API clients/tokens, append-only audit_log, signing_keys, devices, agents, agent_certificates, commands, patch, software, vuln, DEX, inventory, licenses, backup_runs |
| 0002_timescale | hypertables, compression, continuous aggregates (needs TimescaleDB) |
| 0003_seed_roles | console roles (re-runnable) |
| 0004_db_roles | least-privilege DB roles aegis_app / aegis_readonly / aegis_backup_operator (re-runnable; run again after any new migration) |
| 0005_enterprise_inventory_patch | device identity + rich attributes, NICs/IPs/disks/security posture, custom attributes, dynamic groups, user_scopes, patch catalog fields, patch_cves, patch_supersedence, applicability rules, **device_patch_state** (hash-partitioned, compliance source of truth), policies/SLA, maintenance & blackout windows, rings, approvals, compliance views + daily snapshots |
| 0006_enterprise_timescale | compliance snapshot hypertables + nightly job |
| 0007_ingestion_support | system_settings, agent_config_profiles, **agent_stream_offsets** (dedup), content_feeds, unmatched_patch_reports, agent_releases, alerts |

Rules:
- Migrations run **once** each (use golang-migrate or similar to track). Never edit an
  applied migration - add a new numbered file.
- The app connects as a login role in `aegis_app`, **never** as postgres/owner.
- audit_log is append-only (triggers block UPDATE/DELETE/TRUNCATE).

## Contract rules (proto/aegis/agent/v1)
- Agent identity comes from the **mTLS client cert fingerprint**, never from a message field.
- `SignedEnvelope.signed_content` = serialized `SignedContent` (oneof). Verify the signature
  over the exact bytes **before** parsing; check the oneof type matches the field it came in.
- Command checks on the agent: signature + trusted key + purpose, target_agent_id, expiry
  (server-corrected time), idempotency_key.
- Dedup: every non-heartbeat agent message has (stream, sequence). Server applies only if
  `sequence > agent_stream_offsets.last_sequence` (UPDATE ... WHERE last_sequence < $seq).
  Ack only after durable hand-off; agent then drops it from its local buffer.
- Inventory is delta by **section**: present section replaces it, absent = unchanged.
  state_hash mismatch -> RequestFullSync.
- Patch scan = full snapshot of applicable updates. Only a SUCCEEDED scan may delete
  stale device_patch_state rows; PARTIAL/FAILED scans upsert only. Unknown identifiers ->
  unmatched_patch_reports.
- Vulnerability findings are computed **server-side** from inventory + patch state.
- `buf lint` must pass; `buf breaking` against main must pass (never reuse field numbers).

## Ingestion architecture (to build next)
```
Agent -> gRPC stream (mTLS) -> auth by cert -> validate + dedup -> queue -> batch writer -> Postgres
```
- Don't write to Postgres per message at 50k agents. Batch: COPY for heartbeats/DEX,
  upserts for state tables. Use pgx.
- Server sends Throttle under load; agents reconnect with backoff + jitter.

## Next steps (in order)
1. Go server skeleton: cmd/server, internal/{config,db,grpcserver,enroll,ingest,crypto},
   structured logging, graceful shutdown, /healthz /readyz.
2. EnrollmentService.Enroll: token hash lookup, CSR signing (internal dev CA for now),
   create device + agent + agent_certificates rows, audit_log entry.
3. AgentService.Connect: Hello/HelloAck, Heartbeat -> agent_heartbeats + agents.last_heartbeat_at.
4. Inventory ingestion with dedup -> devices + child tables.
5. Then patch scan ingestion -> device_patch_state.
Write unit tests alongside code (CI: lint, test, SAST, image scan, SBOM).

## Dev environment
- Windows + VS Code + Go 1.27. DB on an Ubuntu 22.04 VM, reached from Windows through an
  SSH tunnel (`ssh -L 5432:localhost:5432 <UBUNTU_USER>@<DB_HOST>`), so the app uses
  `localhost:5432` in dev. Credentials only in a local `.env` that is git-ignored.

## Known open items (don't silently decide these)
- In-process bus vs embedded NATS; v1 secrets store; DB backup/HA strategy; air-gapped
  patch content import flow; CERT-In / STQC / GeM compliance track (legal, not code).
