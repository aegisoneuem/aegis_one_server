package patchfeed

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

// When the MSRC feed takes over a KB an agent reported first, the CVE links
// it confirms become feed links (and may then flag has_kev); the agent's other
// claims stay 'agent_report' and never do (0030).
func TestSyncConfirmsAgentLinksDB(t *testing.T) {
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
	confirmed := "CVE-2026-" + strconv.FormatInt(60000+n.Int64(), 10) // on KEV, feed confirms it
	planted := "CVE-2026-" + strconv.FormatInt(61000+n.Int64(), 10)   // on KEV, only the agent says so

	// What an endpoint's scan report leaves behind (ingest.enrichAgentPatch).
	var patchID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO patch_catalog (vendor, product, kb_or_advisory_id, title, severity, catalog_source)
		VALUES ('microsoft', 'Windows', $1, 'agent title', 'unrated', 'agent_report') RETURNING id`, kb).Scan(&patchID); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{confirmed, planted} {
		if _, err := pool.Exec(ctx, `INSERT INTO cve_catalog (cve_id, is_kev, kev_added_at) VALUES ($1, true, current_date)`, c); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO patch_cves (patch_id, cve_id, source) VALUES ($1, $2, 'agent_report')`, patchID, c); err != nil {
			t.Fatal(err)
		}
	}

	var sum Summary
	err = runSync(ctx, pool,
		map[string]*CVEDetail{confirmed: {CVEID: confirmed, Description: "d", Severity: "critical"}},
		map[string]*KBRecord{kb: {KB: kb, Title: "feed title", CVEIDs: []string{confirmed}, Severity: "critical"}},
		&sum)
	if err != nil {
		t.Fatalf("runSync: %v", err)
	}

	var source, severity string
	var hasKEV bool
	if err := pool.QueryRow(ctx, `SELECT catalog_source, severity, has_kev FROM patch_catalog WHERE id = $1`, patchID).
		Scan(&source, &severity, &hasKEV); err != nil {
		t.Fatal(err)
	}
	if source != "msrc" || severity != "critical" || !hasKEV {
		t.Errorf("after takeover: source %q severity %q has_kev %v", source, severity, hasKEV)
	}
	links := map[string]string{}
	rows, err := pool.Query(ctx, `SELECT cve_id, source FROM patch_cves WHERE patch_id = $1`, patchID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c, s string
		if err := rows.Scan(&c, &s); err != nil {
			t.Fatal(err)
		}
		links[c] = s
	}
	rows.Close()
	if links[confirmed] != "msrc" || links[planted] != "agent_report" || len(links) != 2 {
		t.Errorf("links after takeover: %v", links)
	}

	// Un-flag the confirmed CVE: the planted link alone must not keep has_kev.
	if _, err := pool.Exec(ctx, `UPDATE cve_catalog SET is_kev = false WHERE cve_id = $1`, confirmed); err != nil {
		t.Fatal(err)
	}
	if err := runSync(ctx, pool, map[string]*CVEDetail{}, map[string]*KBRecord{}, &sum); err != nil {
		t.Fatalf("runSync (empty): %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT has_kev FROM patch_catalog WHERE id = $1`, patchID).Scan(&hasKEV); err != nil {
		t.Fatal(err)
	}
	if hasKEV {
		t.Error("the agent's unconfirmed KEV link kept has_kev set")
	}
}
