-- =====================================================================================
-- AEGIS ONE - Database Schema v2
-- File 4 of 4: 0004_db_roles.sql
-- Least-privilege DATABASE roles (separate from the console roles in 0003).
-- These are NOLOGIN group roles - no passwords in this file. Real login users are created
-- afterwards and their passwords come from Vault / your secret store.
-- Run this file LAST (after 0001-0003) so the grants cover every table and view.
-- Needs PostgreSQL 14+ (uses the built-in pg_read_all_data role).
-- =====================================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
        CREATE ROLE aegis_app NOLOGIN;              -- the application server
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_readonly') THEN
        CREATE ROLE aegis_readonly NOLOGIN;         -- reporting / BI
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_backup_operator') THEN
        CREATE ROLE aegis_backup_operator NOLOGIN;  -- pg_dump / backup jobs only
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO aegis_app, aegis_readonly, aegis_backup_operator;

-- Application: normal read/write ...
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aegis_app;
-- ... except audit_log, which it may only append to.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM aegis_app;

-- Reporting: read everything except credential/secret-bearing tables.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO aegis_readonly;
REVOKE SELECT ON users, api_tokens, enrollment_tokens, licenses FROM aegis_readonly;

-- Backup operator: read-all for pg_dump, nothing else (no writes, no DDL).
GRANT pg_read_all_data TO aegis_backup_operator;

-- Tables created later by the same migration user inherit the app/reporting grants.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegis_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO aegis_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO aegis_readonly;
