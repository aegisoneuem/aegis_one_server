// synckev imports CISA's Known Exploited Vulnerabilities catalog: flags
// cve_catalog.is_kev, recomputes patch_catalog.has_kev, and tightens open
// patch SLAs to the KEV deadline.
//
// Usage: go run ./cmd/synckev
//
// Without AEGIS_DATABASE_URL set, it fetches and validates but only prints a
// summary (dry run) - nothing is written.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"aegis-one/internal/config"
	"aegis-one/internal/db"
	"aegis-one/internal/kev"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fmt.Println("fetching CISA KEV catalog ...")
	cat, err := kev.Fetch(ctx)
	if err != nil {
		fatalf("fetch failed: %v", err)
	}
	ms := 0
	for _, v := range cat.Vulnerabilities {
		if strings.Contains(strings.ToLower(v.VendorProject), "microsoft") {
			ms++
		}
	}
	fmt.Printf("catalog %s: %d entries (%d Microsoft)\n", cat.CatalogVersion, len(cat.Vulnerabilities), ms)

	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		fmt.Println("AEGIS_DATABASE_URL not set - dry run only, nothing written.")
		return
	}
	pool, err := db.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fatalf("database connection failed: %v", err)
	}
	defer pool.Close()

	s, err := kev.Sync(ctx, pool, cat)
	if err != nil {
		fatalf("sync failed (changes rolled back): %v", err)
	}
	fmt.Printf("done: %d CVE added, %d newly flagged, %d un-flagged, %d patch has_kev changed, %d deadlines tightened\n",
		s.CVEsAdded, s.CVEsFlagged, s.CVEsUnflagged, s.PatchesChanged, s.DeadlinesTightened)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "synckev: "+format+"\n", args...)
	os.Exit(1)
}
