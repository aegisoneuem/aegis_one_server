package kev

// Integration test; skipped unless AEGIS_TEST_DATABASE_URL points at a throwaway
// database with all migrations applied. Creates its own rows, deletes nothing.

import (
	"context"
	"crypto/rand"
	"math/big"
	"os"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Apply flags a patch known-exploited only through links the vendor feed
// asserted: a link an agent reported for a KEV CVE must not count (0030).
func TestApplyIgnoresAgentLinksDB(t *testing.T) {
	url := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	kb := "KB" + strconv.FormatInt(7000000+n.Int64(), 10)
	cve := "CVE-2026-" + strconv.FormatInt(50000+n.Int64(), 10)
	var patchID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO patch_catalog (vendor, product, kb_or_advisory_id, title, severity, catalog_source)
		VALUES ('microsoft', 'Windows', $1, 'agent-reported', 'unrated', 'agent_report') RETURNING id`, kb).Scan(&patchID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cve_catalog (cve_id, is_kev, kev_added_at) VALUES ($1, true, current_date)`, cve); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO patch_cves (patch_id, cve_id, source) VALUES ($1, $2, 'agent_report')`, patchID, cve); err != nil {
		t.Fatal(err)
	}

	apply := func() {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Apply(ctx, tx); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			t.Fatalf("Apply: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	hasKEV := func() bool {
		t.Helper()
		var v bool
		if err := pool.QueryRow(ctx, `SELECT has_kev FROM patch_catalog WHERE id = $1`, patchID).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	apply()
	if hasKEV() {
		t.Fatal("an agent-reported link to a KEV CVE flagged the patch has_kev")
	}
	// The same link asserted by the feed does count.
	if _, err := pool.Exec(ctx, `UPDATE patch_cves SET source = 'msrc' WHERE patch_id = $1 AND cve_id = $2`, patchID, cve); err != nil {
		t.Fatal(err)
	}
	apply()
	if !hasKEV() {
		t.Fatal("a feed link to a KEV CVE did not flag the patch has_kev")
	}
	// The link's source is constrained to the two known values.
	if _, err := pool.Exec(ctx, `INSERT INTO patch_cves (patch_id, cve_id, source) VALUES ($1, 'CVE-2026-1', 'console')`, patchID); err == nil {
		t.Error("patch_cves accepted an unknown source")
	}
}
