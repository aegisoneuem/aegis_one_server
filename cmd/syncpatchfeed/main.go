// syncpatchfeed imports one month's Microsoft security update metadata (CVE, KB,
// severity, product applicability) from the official MSRC CVRF API into
// patch_catalog / cve_catalog / patch_cves / patch_applicability_rules.
//
// Usage:
//
//	go run ./cmd/syncpatchfeed [document-id]   # e.g. 2026-Sep; defaults to latest
//
// Without AEGIS_DATABASE_URL set, it fetches and parses but only prints a summary
// (dry run) - nothing is written.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"aegis-one/internal/config"
	"aegis-one/internal/db"
	"aegis-one/internal/msrc"
	"aegis-one/internal/patchfeed"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := config.Load()
	client := msrc.NewClient()

	documentID := ""
	if len(os.Args) > 1 {
		documentID = os.Args[1]
	}
	if documentID == "" {
		id, err := client.LatestUpdateID(ctx)
		if err != nil {
			fatalf("could not determine latest MSRC document: %v", err)
		}
		documentID = id
	}

	fmt.Printf("fetching MSRC CVRF document %s ...\n", documentID)
	doc, err := client.FetchDocument(ctx, documentID)
	if err != nil {
		fatalf("fetch failed: %v", err)
	}

	cves, kbs := patchfeed.Extract(doc)
	fmt.Printf("parsed: %d CVE(s), %d KB(s)\n", len(cves), len(kbs))

	if cfg.DatabaseURL == "" {
		fmt.Println("AEGIS_DATABASE_URL not set - dry run only, nothing written.")
		printSample(kbs)
		return
	}

	pool, err := db.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fatalf("database connection failed: %v", err)
	}
	defer pool.Close()

	summary, err := patchfeed.Sync(ctx, pool, documentID, cves, kbs)
	if err != nil {
		fatalf("sync failed (partially applied changes were rolled back): %v", err)
	}

	fmt.Printf("done: %d CVE added, %d CVE updated, %d patch added, %d patch updated, %d applicability rules, %d supersedence links, %d patch has_kev changed, %d deadlines tightened\n",
		summary.CVEsAdded, summary.CVEsUpdated, summary.PatchesAdded, summary.PatchesUpdated,
		summary.ApplicabilityRules, summary.SupersedenceLinks, summary.KEVPatchesChanged, summary.DeadlinesTightened)
}

func printSample(kbs map[string]*patchfeed.KBRecord) {
	n := 0
	for _, kb := range kbs {
		fmt.Printf("  %-10s severity=%-8s cves=%d products=%d title=%q\n",
			kb.KB, kb.Severity, len(kb.CVEIDs), len(kb.Products), kb.Title)
		n++
		if n >= 5 {
			fmt.Printf("  ... and %d more\n", len(kbs)-n)
			break
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "syncpatchfeed: "+format+"\n", args...)
	os.Exit(1)
}
