# Database migrations on deploy

The schema lives in `db/migrations/NNNN_name.sql`. Those files are compiled into
the `migrate` tool (`cmd/migrate`) and into the server. `schema_migrations`
records which ones have run, so each runs exactly once per database.

## Rules

- **Run `migrate up` on every deploy, before starting the new server.** The
  server refuses to start if the database is missing a migration it ships with.
  You will see `database schema is not current` and the list of pending files.
- `migrate` connects as the **schema owner** (it runs DDL), using
  `AEGIS_MIGRATE_DATABASE_URL`. The server uses its own `aegis_app` login
  (`AEGIS_DATABASE_URL`). Never give the server the owner URL.
- After every run, `0004_db_roles.sql` is applied again, so new tables get the
  least-privilege grants. You no longer run it by hand.
- **Never edit a migration that has been applied.** Add a new numbered file.
  `migrate` refuses to run if an applied file has changed.
- Each migration runs in one transaction. If one fails, it leaves nothing
  behind and the run stops there. Fix it, then run again.
- Only one run at a time: a second concurrent run is refused (advisory lock).

## Commands

```bash
export AEGIS_MIGRATE_DATABASE_URL='postgres://<OWNER_USER>:<OWNER_PASSWORD>@<DB_HOST>:5432/<DB_NAME>?sslmode=require'

go run ./cmd/migrate status      # applied / pending
go run ./cmd/migrate up          # apply pending (+ re-apply 0004)
```

On a server without Go, build the binary once and copy it next to the server:

```bash
go build -o migrate ./cmd/migrate
```

## First deploy: three cases

| Database | What to run |
|---|---|
| New, empty | `migrate up`. Applies 0001 onwards. |
| Migrated **by hand** with psql earlier (e.g. the current dev DB) | Once: `migrate baseline -through 0016` (use the last file it really has), then `migrate up` |
| Already managed by `migrate` | `migrate up` |

`baseline` only *records* files as applied. It does not run them, so set
`-through` to the last migration the database actually has. If unsure, check
whether that migration's tables exist first. For example, 0016 adds
`software_packages.installer_type`, 0017 adds `agent_audit_events`, and 0018
adds `device_patch_not_applicable`.

`migrate up` on a database that has Aegis One tables but no history refuses to
run and tells you to baseline. This guard stops it from re-running 0001 on a
live database.

## Deploy order

1. Back up the database (pg_dump / your backup job).
2. `migrate status`: review what will run.
3. `migrate up`
4. Start the new server version.

The app login role is created once, outside migrations, because its password
comes from the secret store:

```sql
CREATE ROLE <APP_LOGIN> LOGIN PASSWORD '<FROM_SECRET_STORE>' IN ROLE aegis_app;
```
