package ingest

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// assignSLA fills policy_id + sla_due_at on this device's open
// device_patch_state rows that don't have an SLA yet, per 0005's rule: the SLA is
// fixed when a patch is first detected missing, from the device's WINNING
// patch_policy - so a later policy edit doesn't move existing deadlines.
//
// Winning policy: enabled, and fleet-wide (applies_to_group_id NULL) or scoped to
// the device's primary group or any group it's a member of; lowest priority
// wins, a group-specific policy beats the fleet default on a tie.
//
// Days: sla_days_kev if the patch has a known-exploited CVE, otherwise by
// patch_catalog.severity. No SLA (left NULL) when:
//   - the patch's classification isn't in the policy's in_scope_classifications
//   - the severity is 'unrated' - we don't know how urgent it is, so it is never
//     reported overdue rather than guessed at
//   - no enabled policy matches the device at all
//
// Rows left NULL are simply retried on the next scan (cheap - one statement).
func assignSLA(ctx context.Context, tx pgx.Tx, deviceUUID string) (int, error) {
	tag, err := tx.Exec(ctx, `
		WITH pol AS (
			SELECT p.*
			FROM patch_policies p
			JOIN devices d ON d.id = $1
			WHERE p.is_enabled
			  AND (   p.applies_to_group_id IS NULL
			       OR p.applies_to_group_id = d.primary_group_id
			       OR p.applies_to_group_id IN (SELECT m.group_id FROM device_group_membership m WHERE m.device_id = $1))
			ORDER BY p.priority, (p.applies_to_group_id IS NULL), p.created_at
			LIMIT 1
		),
		due AS (
			SELECT s.patch_id, pol.id AS policy_id,
			       s.first_detected_missing_at + make_interval(days =>
			           CASE WHEN pc.has_kev THEN pol.sla_days_kev
			                ELSE CASE pc.severity
			                         WHEN 'critical' THEN pol.sla_days_critical
			                         WHEN 'high'     THEN pol.sla_days_high
			                         WHEN 'medium'   THEN pol.sla_days_medium
			                         WHEN 'low'      THEN pol.sla_days_low
			                     END
			           END) AS sla_due_at
			FROM device_patch_state s
			JOIN patch_catalog pc ON pc.id = s.patch_id
			CROSS JOIN pol
			WHERE s.device_id = $1
			  AND s.state IN ('missing', 'failed', 'pending_reboot')
			  AND s.sla_due_at IS NULL
			  AND s.first_detected_missing_at IS NOT NULL
			  AND pc.classification = ANY(pol.in_scope_classifications)
			  AND (pc.has_kev OR pc.severity <> 'unrated')
		)
		UPDATE device_patch_state s
		SET policy_id = due.policy_id, sla_due_at = due.sla_due_at
		FROM due
		WHERE s.device_id = $1 AND s.patch_id = due.patch_id`, deviceUUID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
