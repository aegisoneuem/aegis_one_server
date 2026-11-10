package msrc

import "testing"

// MSRC revises old documents, so CurrentReleaseDate of a months-old release
// can be the newest; the latest document is the newest *initial* release.
func TestLatestIDUsesInitialReleaseDate(t *testing.T) {
	updates := []UpdateSummary{
		{ID: "2026-Apr", InitialReleaseDate: "2026-04-14T07:00:00Z", CurrentReleaseDate: "2026-11-04T08:00:00Z"},
		{ID: "2026-Oct", InitialReleaseDate: "2026-10-13T07:00:00Z", CurrentReleaseDate: "2026-10-20T08:00:00Z"},
		{ID: "2026-Sep", InitialReleaseDate: "2026-09-08T07:00:00Z", CurrentReleaseDate: "2026-09-08T07:00:00Z"},
		{ID: "", InitialReleaseDate: "2027-01-01T00:00:00Z"}, // junk entry ignored
	}
	got, err := recentIDs(updates, 1)
	if err != nil || len(got) != 1 || got[0] != "2026-Oct" {
		t.Fatalf("recentIDs(1) = %v, %v; want [2026-Oct]", got, err)
	}
	// The two newest, oldest first, so syncing in order lets the newest win.
	got, err = recentIDs(updates, 2)
	if err != nil || len(got) != 2 || got[0] != "2026-Sep" || got[1] != "2026-Oct" {
		t.Fatalf("recentIDs(2) = %v, %v; want [2026-Sep 2026-Oct]", got, err)
	}
	if got, _ := recentIDs(updates, 10); len(got) != 3 || got[0] != "2026-Apr" {
		t.Fatalf("recentIDs(10) = %v; want all 3, oldest first", got)
	}
	if _, err := recentIDs(nil, 2); err == nil {
		t.Fatal("no updates must be an error")
	}
}
