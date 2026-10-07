package patchfeed

import (
	"context"
	"fmt"
	"strings"
	"time"

	"aegis-one/internal/feedrun"
	"aegis-one/internal/kev"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var feed = feedrun.Feed{Name: "microsoft_cvrf", Type: "patch_metadata", SourceURL: "https://api.msrc.microsoft.com/cvrf/v3.0"}

type Summary struct {
	DocumentID         string
	CVEsSeen           int
	KBsSeen            int
	CVEsAdded          int
	CVEsUpdated        int
	PatchesAdded       int
	PatchesUpdated     int
	ApplicabilityRules int
	SupersedenceLinks  int
	KEVPatchesChanged  int
	DeadlinesTightened int
}

// Sync upserts the extracted CVE/KB data for one MSRC document into Postgres,
// recording the attempt in content_feeds/feed_sync_runs either way.
func Sync(ctx context.Context, pool *pgxpool.Pool, documentID string, cves map[string]*CVEDetail, kbs map[string]*KBRecord) (Summary, error) {
	summary := Summary{DocumentID: documentID, CVEsSeen: len(cves), KBsSeen: len(kbs)}
	err := feedrun.Track(ctx, pool, feed, documentID, func() (int, int, error) {
		err := runSync(ctx, pool, cves, kbs, &summary)
		return summary.PatchesAdded + summary.CVEsAdded, summary.PatchesUpdated + summary.CVEsUpdated, err
	})
	return summary, err
}

func runSync(ctx context.Context, pool *pgxpool.Pool, cves map[string]*CVEDetail, kbs map[string]*KBRecord, summary *Summary) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	for _, cve := range cves {
		inserted, err := upsertCVE(ctx, tx, cve)
		if err != nil {
			return fmt.Errorf("upsert cve %s: %w", cve.CVEID, err)
		}
		if inserted {
			summary.CVEsAdded++
		} else {
			summary.CVEsUpdated++
		}
	}

	patchIDs := make(map[string]string, len(kbs)) // KB -> patch_catalog.id
	for _, kb := range kbs {
		id, inserted, err := upsertPatch(ctx, tx, kb)
		if err != nil {
			return fmt.Errorf("upsert patch %s: %w", kb.KB, err)
		}
		patchIDs[kb.KB] = id
		if inserted {
			summary.PatchesAdded++
		} else {
			summary.PatchesUpdated++
		}

		for _, cveID := range kb.CVEIDs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO patch_cves (patch_id, cve_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
				id, cveID); err != nil {
				return fmt.Errorf("link patch %s to cve %s: %w", kb.KB, cveID, err)
			}
		}

		if _, err := tx.Exec(ctx, `DELETE FROM patch_applicability_rules WHERE patch_id = $1`, id); err != nil {
			return fmt.Errorf("clear applicability rules for %s: %w", kb.KB, err)
		}
		for _, product := range kb.Products {
			if _, err := tx.Exec(ctx, `
				INSERT INTO patch_applicability_rules (patch_id, os_family, product_name_pattern)
				VALUES ($1, $2, $3)`,
				id, guessOSFamily(product), product); err != nil {
				return fmt.Errorf("insert applicability rule for %s: %w", kb.KB, err)
			}
			summary.ApplicabilityRules++
		}
	}

	for _, kb := range kbs {
		if kb.Supersedes == "" {
			continue
		}
		supersededID, ok := patchIDs[kb.Supersedes]
		if !ok {
			// Not in this month's document; it may already be in the catalog from an
			// earlier sync run.
			err := tx.QueryRow(ctx,
				`SELECT id FROM patch_catalog WHERE vendor = 'microsoft' AND kb_or_advisory_id = $1`,
				kb.Supersedes).Scan(&supersededID)
			if err == pgx.ErrNoRows {
				continue // superseded KB not in our catalog yet; nothing to link
			}
			if err != nil {
				return fmt.Errorf("look up superseded patch %s: %w", kb.Supersedes, err)
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO patch_supersedence (superseding_patch_id, superseded_patch_id)
			VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			patchIDs[kb.KB], supersededID); err != nil {
			return fmt.Errorf("link supersedence %s -> %s: %w", kb.KB, kb.Supersedes, err)
		}
		summary.SupersedenceLinks++
	}

	// New patch->CVE links may point at CVEs already flagged by the KEV feed.
	if summary.KEVPatchesChanged, summary.DeadlinesTightened, err = kev.Apply(ctx, tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func upsertCVE(ctx context.Context, tx pgx.Tx, cve *CVEDetail) (inserted bool, err error) {
	err = tx.QueryRow(ctx, `
		INSERT INTO cve_catalog (cve_id, description, cvss_score, cvss_vector, severity, published_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (cve_id) DO UPDATE SET
			description  = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE cve_catalog.description END,
			cvss_score   = COALESCE(EXCLUDED.cvss_score, cve_catalog.cvss_score),
			cvss_vector  = COALESCE(NULLIF(EXCLUDED.cvss_vector, ''), cve_catalog.cvss_vector),
			severity     = EXCLUDED.severity,
			updated_at   = now()
		RETURNING (xmax = 0)`,
		cve.CVEID, cve.Description, cve.CVSSScore, nullIfEmpty(cve.CVSSVector), cve.Severity, nullIfZeroDate(cve.PublishedAt),
	).Scan(&inserted)
	return inserted, err
}

func upsertPatch(ctx context.Context, tx pgx.Tx, kb *KBRecord) (id string, inserted bool, err error) {
	product := "Windows"
	if len(kb.Products) > 0 {
		product = kb.Products[0]
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO patch_catalog (vendor, product, kb_or_advisory_id, title, severity, release_date, is_esu, source_url)
		VALUES ('microsoft', $1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (vendor, kb_or_advisory_id) DO UPDATE SET
			product      = EXCLUDED.product,
			title        = EXCLUDED.title,
			severity     = EXCLUDED.severity,
			release_date = EXCLUDED.release_date,
			is_esu       = EXCLUDED.is_esu,
			source_url   = EXCLUDED.source_url
		RETURNING id, (xmax = 0)`,
		product, kb.KB, kb.Title, kb.Severity, nullIfZeroDate(kb.ReleaseDate), kb.IsESU, nullIfEmpty(kb.SourceURL),
	).Scan(&id, &inserted)
	return id, inserted, err
}

// guessOSFamily is a best-effort heuristic from the MSRC product display name -
// most CVRF Windows Update documents are Windows/Edge products, but the feed also
// carries a handful of Linux (Mariner) and other entries.
func guessOSFamily(product string) string {
	p := strings.ToLower(product)
	switch {
	case strings.Contains(p, "linux"), strings.Contains(p, "mariner"):
		return "linux"
	case strings.Contains(p, "macos"), strings.Contains(p, "mac os"):
		return "macos"
	default:
		return "windows"
	}
}

func nullIfEmpty(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

func nullIfZeroDate(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
