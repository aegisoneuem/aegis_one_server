package msrc

import "testing"

// MSRC revises old documents, so CurrentReleaseDate of a months-old release
// can be the newest; the latest document is the newest *initial* release.
func TestLatestIDUsesInitialReleaseDate(t *testing.T) {
	got, err := latestID([]UpdateSummary{
		{ID: "2026-Apr", InitialReleaseDate: "2026-04-14T07:00:00Z", CurrentReleaseDate: "2026-11-04T08:00:00Z"},
		{ID: "2026-Oct", InitialReleaseDate: "2026-10-13T07:00:00Z", CurrentReleaseDate: "2026-10-20T08:00:00Z"},
		{ID: "2026-Sep", InitialReleaseDate: "2026-09-08T07:00:00Z", CurrentReleaseDate: "2026-09-08T07:00:00Z"},
	})
	if err != nil || got != "2026-Oct" {
		t.Fatalf("latestID = %q, %v; want 2026-Oct", got, err)
	}
	if _, err := latestID(nil); err == nil {
		t.Fatal("no updates must be an error")
	}
}
