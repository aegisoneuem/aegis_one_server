-- 0010_default_patch_policy.sql
-- Fleet-wide fallback patch policy (applies_to_group_id NULL). Without at least one
-- enabled policy, internal/ingest can't resolve an SLA for any device, so
-- device_patch_state.sla_due_at stays NULL and nothing is ever overdue or
-- non_compliant. SLA days are NOT chosen here - every value comes from the
-- patch_policies column defaults set in 0005 (critical 7, high 14, medium 30,
-- low 90, KEV 3). Priority 1000 so any group-specific policy (default 100) wins.
-- Re-runnable.
INSERT INTO patch_policies (name, description, priority)
VALUES ('Fleet default', 'Fallback SLA policy for devices no group policy covers', 1000)
ON CONFLICT (name) DO NOTHING;
