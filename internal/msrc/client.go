// Package msrc is a client for the official Microsoft Security Response Center
// CVRF v3.0 API (https://api.msrc.microsoft.com/cvrf/v3.0) - our own patch/CVE
// metadata source, independent of any third-party tooling. No API key required.
// One Document corresponds to one month's security update release (e.g. "2026-Sep").
package msrc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const baseURL = "https://api.msrc.microsoft.com/cvrf/v3.0"

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{httpClient: &http.Client{Timeout: 30 * time.Second}}
}

// UpdateSummary is one entry from GET /updates: the index of available monthly
// CVRF documents.
type UpdateSummary struct {
	ID                 string `json:"ID"`
	DocumentTitle      string `json:"DocumentTitle"`
	InitialReleaseDate string `json:"InitialReleaseDate"`
	CurrentReleaseDate string `json:"CurrentReleaseDate"`
	CvrfURL            string `json:"CvrfUrl"`
}

type updatesResponse struct {
	Value []UpdateSummary `json:"value"`
}

// ListUpdates returns every monthly CVRF document MSRC has published.
func (c *Client) ListUpdates(ctx context.Context) ([]UpdateSummary, error) {
	var out updatesResponse
	if err := c.getJSON(ctx, baseURL+"/updates", &out); err != nil {
		return nil, err
	}
	return out.Value, nil
}

// LatestUpdateID returns the ID (e.g. "2026-Sep") of the most recently released
// monthly document.
func (c *Client) LatestUpdateID(ctx context.Context) (string, error) {
	updates, err := c.ListUpdates(ctx)
	if err != nil {
		return "", err
	}
	var latestID, latestDate string
	for _, u := range updates {
		if u.CurrentReleaseDate > latestDate {
			latestDate, latestID = u.CurrentReleaseDate, u.ID
		}
	}
	if latestID == "" {
		return "", fmt.Errorf("msrc: no updates returned")
	}
	return latestID, nil
}

// Document is a single monthly CVRF release: one vulnerability per CVE, with
// product applicability, severity, CVSS and remediation (KB) data.
type Document struct {
	DocumentTitle    TextValue        `json:"DocumentTitle"`
	DocumentTracking DocumentTracking `json:"DocumentTracking"`
	ProductTree      ProductTree      `json:"ProductTree"`
	Vulnerability    []Vulnerability  `json:"Vulnerability"`
}

type DocumentTracking struct {
	Identification struct {
		ID TextValue `json:"ID"`
	} `json:"Identification"`
	InitialReleaseDate string `json:"InitialReleaseDate"`
	CurrentReleaseDate string `json:"CurrentReleaseDate"`
}

type TextValue struct {
	Value string `json:"Value"`
}

// ProductTree is an arbitrarily nested tree; leaves carry ProductID+Value,
// branches carry Items (recursively) and no ProductID. See FlattenProducts.
type ProductTree struct {
	Branch []ProductBranch `json:"Branch"`
}

type ProductBranch struct {
	Items []ProductNode `json:"Items"`
}

type ProductNode struct {
	ProductID string        `json:"ProductID,omitempty"`
	Value     string        `json:"Value,omitempty"`
	Items     []ProductNode `json:"Items,omitempty"`
}

// FlattenProducts walks the nested ProductTree and returns a flat ProductID -> display
// name map (e.g. "11568" -> "Windows 10 Version 1809 for 32-bit Systems").
func (t ProductTree) FlattenProducts() map[string]string {
	out := make(map[string]string)
	var walk func(nodes []ProductNode)
	walk = func(nodes []ProductNode) {
		for _, n := range nodes {
			if n.ProductID != "" {
				out[n.ProductID] = n.Value
			}
			if len(n.Items) > 0 {
				walk(n.Items)
			}
		}
	}
	for _, b := range t.Branch {
		walk(b.Items)
	}
	return out
}

type Vulnerability struct {
	Title         TextValue      `json:"Title"`
	Notes         []Note         `json:"Notes"`
	CVE           string         `json:"CVE"`
	Threats       []Threat       `json:"Threats"`
	CVSSScoreSets []CVSSScoreSet `json:"CVSSScoreSets"`
	Remediations  []Remediation  `json:"Remediations"`
}

// NoteTypeDescription is the CVRF Notes[].Type value carrying the CVE's prose
// description, confirmed against a live document.
const NoteTypeDescription = 2

type Note struct {
	Title string `json:"Title"`
	Type  int    `json:"Type"`
	Value string `json:"Value"`
}

// ThreatTypeSeverity is the CVRF Threats[].Type value whose Description carries the
// MSRC severity rating ("Critical" | "Important" | "Moderate" | "Low"), confirmed
// against a live document (api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep).
const ThreatTypeSeverity = 3

type Threat struct {
	Description TextValue `json:"Description"`
	ProductID   []string  `json:"ProductID"`
	Type        int       `json:"Type"`
}

type CVSSScoreSet struct {
	BaseScore float64  `json:"BaseScore"`
	Vector    string   `json:"Vector"`
	ProductID []string `json:"ProductID"`
}

// RemediationTypeVendorFix is the CVRF Remediations[].Type value for the actual
// vendor fix, whose Description carries the bare KB number (e.g. "5122876") and
// whose URL points at the Microsoft Update Catalog - confirmed against a live
// document.
const RemediationTypeVendorFix = 2

type Remediation struct {
	Description  TextValue `json:"Description"`
	URL          string    `json:"URL"`
	Supercedence string    `json:"Supercedence"`
	ProductID    []string  `json:"ProductID"`
	Type         int       `json:"Type"`
	SubType      string    `json:"SubType"`
	FixedBuild   string    `json:"FixedBuild"`
}

// FetchDocument retrieves and parses one monthly CVRF document by its ID (e.g. "2026-Sep").
func (c *Client) FetchDocument(ctx context.Context, documentID string) (*Document, error) {
	var doc Document
	url := fmt.Sprintf("%s/cvrf/%s", baseURL, documentID)
	if err := c.getJSON(ctx, url, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (c *Client) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("msrc: request %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("msrc: %s returned %d: %s", url, resp.StatusCode, string(body))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("msrc: decode %s: %w", url, err)
	}
	return nil
}
