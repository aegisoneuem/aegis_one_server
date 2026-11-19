package compliance

// Integration test; skipped unless AEGIS_TEST_DATABASE_URL points at a throwaway
// database with all migrations applied.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The compliance views must have the columns the readers select (0029 added
// catalog_source to patch_compliance_by_patch).
func TestViewsReadableDB(t *testing.T) {
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

	rows, err := ListPatches(ctx, pool)
	if err != nil {
		t.Fatalf("ListPatches: %v", err)
	}
	for _, r := range rows {
		if r.Source != "msrc" && r.Source != "agent_report" {
			t.Errorf("patch %s: catalog_source %q", r.KB, r.Source)
		}
		if r.Source == "agent_report" && r.Severity != "unrated" {
			t.Errorf("agent-reported patch %s rated %q", r.KB, r.Severity)
		}
	}
	if _, err := ListDevices(ctx, pool); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
}
