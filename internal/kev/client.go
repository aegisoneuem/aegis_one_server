// Package kev imports CISA's Known Exploited Vulnerabilities catalog - the
// official public JSON feed, no API key - and applies it: flags cve_catalog,
// recomputes the denormalized patch_catalog.has_kev, and tightens open SLAs.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const SourceURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Catalog mirrors the feed's top level; field names verified against the live
// feed (catalogVersion 2026.10.02, 1733 entries).
type Catalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"` // YYYY-MM-DD
	ShortDescription           string `json:"shortDescription"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

func Fetch(ctx context.Context) (*Catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, SourceURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("kev: %s returned %d: %s", SourceURL, resp.StatusCode, body)
	}

	var cat Catalog
	if err := json.NewDecoder(resp.Body).Decode(&cat); err != nil {
		return nil, fmt.Errorf("kev: decode: %w", err)
	}
	// Fail closed: Sync un-flags any CVE missing from the catalog, so a truncated
	// or empty response must never be applied.
	if len(cat.Vulnerabilities) == 0 || len(cat.Vulnerabilities) != cat.Count {
		return nil, fmt.Errorf("kev: catalog looks incomplete (count=%d, entries=%d) - refusing to use it", cat.Count, len(cat.Vulnerabilities))
	}
	return &cat, nil
}
