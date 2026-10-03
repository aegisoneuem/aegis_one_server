// Package patchfeed turns an MSRC CVRF document into our own patch_catalog /
// cve_catalog / patch_cves / patch_applicability_rules rows - the "own" patch
// metadata feed (deliberately not the BigFix fixlet-gen tooling).
package patchfeed

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"aegis-one/internal/msrc"
)

// CVEDetail is what we keep per CVE, independent of which KB(s) fix it.
type CVEDetail struct {
	CVEID       string
	Description string
	CVSSScore   *float64
	CVSSVector  string
	Severity    string // critical | high | medium | low | unrated
	PublishedAt time.Time
}

// KBRecord is one vendor fix (KB), aggregated across every CVE it remediates.
type KBRecord struct {
	KB          string // "KB5122876"
	Title       string
	CVEIDs      []string
	Severity    string // worst severity across its CVEs
	CVSSScore   *float64
	CVSSVector  string
	SourceURL   string
	Supersedes  string // "KB5120418" or ""
	Products    []string
	IsESU       bool
	ReleaseDate time.Time
}

var kbDigits = regexp.MustCompile(`^\d{6,7}$`)

var severityRank = map[string]int{"unrated": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func mapSeverity(msrcSeverity string) string {
	switch strings.ToLower(strings.TrimSpace(msrcSeverity)) {
	case "critical":
		return "critical"
	case "important":
		return "high"
	case "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return "unrated"
	}
}

func worseSeverity(a, b string) string {
	if severityRank[b] > severityRank[a] {
		return b
	}
	return a
}

// Extract parses doc into per-CVE details and per-KB records.
func Extract(doc *msrc.Document) (cves map[string]*CVEDetail, kbs map[string]*KBRecord) {
	products := doc.ProductTree.FlattenProducts()
	releaseDate := parseDate(doc.DocumentTracking.InitialReleaseDate)

	cves = make(map[string]*CVEDetail)
	kbs = make(map[string]*KBRecord)

	for _, v := range doc.Vulnerability {
		if v.CVE == "" {
			continue
		}

		cve := cves[v.CVE]
		if cve == nil {
			cve = &CVEDetail{CVEID: v.CVE, Severity: "unrated", PublishedAt: releaseDate}
			cves[v.CVE] = cve
		}
		for _, n := range v.Notes {
			if n.Type == msrc.NoteTypeDescription && n.Value != "" {
				cve.Description = n.Value
				break
			}
		}
		if len(v.CVSSScoreSets) > 0 {
			score := v.CVSSScoreSets[0].BaseScore
			cve.CVSSScore = &score
			cve.CVSSVector = v.CVSSScoreSets[0].Vector
		}
		for _, t := range v.Threats {
			if t.Type == msrc.ThreatTypeSeverity && t.Description.Value != "" {
				cve.Severity = worseSeverity(cve.Severity, mapSeverity(t.Description.Value))
				break
			}
		}

		productNamesFor := func(ids []string) []string {
			names := make([]string, 0, len(ids))
			for _, id := range ids {
				if name, ok := products[id]; ok {
					names = append(names, name)
				}
			}
			return names
		}

		for _, r := range v.Remediations {
			if r.Type != msrc.RemediationTypeVendorFix {
				continue
			}
			kbNum := strings.TrimSpace(r.Description.Value)
			if !kbDigits.MatchString(kbNum) {
				continue
			}
			kbID := "KB" + kbNum

			rec := kbs[kbID]
			if rec == nil {
				rec = &KBRecord{KB: kbID, Severity: "unrated", ReleaseDate: releaseDate}
				kbs[kbID] = rec
			}
			rec.Severity = worseSeverity(rec.Severity, cve.Severity)
			if !containsStr(rec.CVEIDs, v.CVE) {
				rec.CVEIDs = append(rec.CVEIDs, v.CVE)
			}
			if rec.SourceURL == "" && r.URL != "" {
				rec.SourceURL = r.URL
			}
			if rec.Supersedes == "" && r.Supercedence != "" {
				rec.Supersedes = "KB" + strings.TrimSpace(r.Supercedence)
			}
			for _, name := range productNamesFor(r.ProductID) {
				if !containsStr(rec.Products, name) {
					rec.Products = append(rec.Products, name)
				}
				if strings.Contains(strings.ToUpper(name), "ESU") {
					rec.IsESU = true
				}
			}
			if rec.CVSSScore == nil && cve.CVSSScore != nil {
				rec.CVSSScore = cve.CVSSScore
				rec.CVSSVector = cve.CVSSVector
			}
		}
	}

	for _, rec := range kbs {
		rec.Title = buildTitle(rec, doc.Vulnerability)
	}

	return cves, kbs
}

// buildTitle picks the single CVE's title when a KB fixes only one, otherwise
// synthesizes a summary rather than arbitrarily picking one of several.
func buildTitle(rec *KBRecord, vulns []msrc.Vulnerability) string {
	if len(rec.CVEIDs) == 1 {
		for _, v := range vulns {
			if v.CVE == rec.CVEIDs[0] && v.Title.Value != "" {
				return v.Title.Value
			}
		}
	}
	primary := "Windows"
	if len(rec.Products) > 0 {
		primary = rec.Products[0]
	}
	return fmt.Sprintf("%s security update (%s) - %d CVE(s) fixed", primary, rec.KB, len(rec.CVEIDs))
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func parseDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return t
	}
	return time.Time{}
}
