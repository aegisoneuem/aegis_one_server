-- =====================================================================================
-- AEGIS ONE - Database Schema v2
-- File 3 of 4: 0003_seed_roles.sql
-- Built-in console roles. Safe to re-run (ON CONFLICT DO NOTHING).
-- No admin USER is seeded on purpose: the first admin should be created by the app's
-- bootstrap step so its password is Argon2-hashed by the app, never typed into SQL.
-- =====================================================================================

INSERT INTO roles (name, permissions, is_system_role) VALUES
    ('admin',
     '{"*": true}',
     true),
    ('operator',
     '{"devices.view": true, "patch.deploy": true, "software.deploy": true, "vuln.scan": true, "reports.view": true}',
     true),
    ('auditor',
     '{"audit.view": true, "devices.view": true, "reports.view": true}',
     true),
    ('read_only',
     '{"devices.view": true, "reports.view": true}',
     true),
    -- Security Review: backups restricted to a dedicated role, not general infra-admin.
    ('backup_operator',
     '{"backup.run": true, "backup.view": true}',
     true)
ON CONFLICT (name) DO NOTHING;
