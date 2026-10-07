package kev

import (
	"context"
	"fmt"

	"aegis-one/internal/feedrun"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var feed = feedrun.Feed{Name: "cisa_kev", Type: "kev", SourceURL: SourceURL}

type Summary struct {
	CatalogVersion     string
	Entries            int
	CVEsAdded          int // KEV CVEs not previously in cve_catalog (inserted)
	CVEsFlagged        int // existing cve_catalog rows newly flagged / kev date changed
	CVEsUnflagged      int // CVEs that dropped off the KEV catalog
	PatchesChanged     int // patch_catalog.has_kev flipped either way
	DeadlinesTightened int // open device_patch_state SLAs pulled in to the KEV deadline
}

// Run fetches the current catalog and syncs it - the unattended path used by
// the feed scheduler. The fetch is inside the tracked run, so an unreachable
// CISA endpoint is recorded as a failed feed_sync_runs row (and backed off).
func Run(ctx context.Context, pool *pgxpool.Pool) (Summary, error) {
	var s Summary
	err := feedrun.Track(ctx, pool, feed, func() (string, int, int, error) {
		cat, err := Fetch(ctx)
		if err != nil {
			return "", 0, 0, err
		}
		err = syncTx(ctx, pool, cat, &s)
		return cat.CatalogVersion, s.CVEsAdded, s.CVEsFlagged + s.CVEsUnflagged, err
	})
	return s, err
}

// Sync applies one already-fetched catalog (cmd/synckev), recorded as a run.
func Sync(ctx context.Context, pool *pgxpool.Pool, cat *Catalog) (Summary, error) {
	var s Summary
	err := feedrun.Track(ctx, pool, feed, func() (string, int, int, error) {
		err := syncTx(ctx, pool, cat, &s)
		return cat.CatalogVersion, s.CVEsAdded, s.CVEsFlagged + s.CVEsUnflagged, err
	})
	return s, err
}

// syncTx applies one KEV catalog as a full snapshot, in one transaction:
//  1. every KEV CVE: is_kev = true, kev_added_at = dateAdded. CVEs we don't
//     have yet are inserted (KEV covers all vendors, not just Microsoft);
//     existing rows keep their MSRC description/severity.
//  2. any CVE flagged earlier but no longer in the catalog is un-flagged.
//  3. Apply: patch_catalog.has_kev + SLA tightening.
func syncTx(ctx context.Context, pool *pgxpool.Pool, cat *Catalog, s *Summary) error {
	s.CatalogVersion, s.Entries = cat.CatalogVersion, len(cat.Vulnerabilities)

	ids := make([]string, len(cat.Vulnerabilities))
	descs := make([]string, len(cat.Vulnerabilities))
	added := make([]string, len(cat.Vulnerabilities))
	for i, v := range cat.Vulnerabilities {
		ids[i], descs[i], added[i] = v.CVEID, v.ShortDescription, v.DateAdded
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	rows, err := tx.Query(ctx, `
		INSERT INTO cve_catalog (cve_id, description, is_kev, kev_added_at)
		SELECT id, descr, true, added::date
		FROM unnest($1::text[], $2::text[], $3::text[]) AS t(id, descr, added)
		ON CONFLICT (cve_id) DO UPDATE SET
			is_kev = true, kev_added_at = EXCLUDED.kev_added_at, updated_at = now()
		WHERE cve_catalog.is_kev IS DISTINCT FROM true
		   OR cve_catalog.kev_added_at IS DISTINCT FROM EXCLUDED.kev_added_at
		RETURNING (xmax = 0)`, ids, descs, added)
	if err != nil {
		return fmt.Errorf("upsert KEV CVEs: %w", err)
	}
	for rows.Next() {
		var inserted bool
		if err := rows.Scan(&inserted); err != nil {
			rows.Close()
			return err
		}
		if inserted {
			s.CVEsAdded++
		} else {
			s.CVEsFlagged++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("upsert KEV CVEs: %w", err)
	}

	tag, err := tx.Exec(ctx, `
		UPDATE cve_catalog SET is_kev = false, kev_added_at = NULL, updated_at = now()
		WHERE is_kev AND NOT (cve_id = ANY($1))`, ids)
	if err != nil {
		return fmt.Errorf("un-flag removed CVEs: %w", err)
	}
	s.CVEsUnflagged = int(tag.RowsAffected())

	if s.PatchesChanged, s.DeadlinesTightened, err = Apply(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

// Apply re-derives patch_catalog.has_kev from cve_catalog.is_kev via patch_cves,
// then tightens open SLAs for KEV patches. Called by Sync and at the end of the
// MSRC patch feed sync (new patch->CVE links can make a patch KEV too).
//
// Tightening rule (not in the schema, a deliberate choice): 0005 fixes an SLA
// when a patch is first detected missing, but CISA usually lists a CVE on or
// after release day - after devices have already detected the patch with a
// severity-based deadline. So an open row's deadline is pulled IN to
// first_detected_missing_at + its policy's sla_days_kev when that is earlier;
// it is never pushed out.
func Apply(ctx context.Context, tx pgx.Tx) (patchesChanged, deadlinesTightened int, err error) {
	tag, err := tx.Exec(ctx, `
		UPDATE patch_catalog p SET has_kev = sub.kev
		FROM (
			SELECT p2.id, EXISTS (
				SELECT 1 FROM patch_cves pc JOIN cve_catalog c ON c.cve_id = pc.cve_id
				WHERE pc.patch_id = p2.id AND c.is_kev) AS kev
			FROM patch_catalog p2
		) sub
		WHERE p.id = sub.id AND p.has_kev IS DISTINCT FROM sub.kev`)
	if err != nil {
		return 0, 0, fmt.Errorf("recompute patch_catalog.has_kev: %w", err)
	}
	patchesChanged = int(tag.RowsAffected())

	tag, err = tx.Exec(ctx, `
		UPDATE device_patch_state s
		SET sla_due_at = s.first_detected_missing_at + make_interval(days => pol.sla_days_kev)
		FROM patch_catalog pc, patch_policies pol
		WHERE pc.id = s.patch_id AND pol.id = s.policy_id
		  AND pc.has_kev
		  AND s.state IN ('missing', 'failed', 'pending_reboot')
		  AND s.sla_due_at IS NOT NULL
		  AND s.first_detected_missing_at + make_interval(days => pol.sla_days_kev) < s.sla_due_at`)
	if err != nil {
		return 0, 0, fmt.Errorf("tighten KEV deadlines: %w", err)
	}
	return patchesChanged, int(tag.RowsAffected()), nil
}
