package ingest

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeKB(t *testing.T) {
	cases := map[string]string{
		"KB5034441":    "KB5034441",
		" kb5034441 ":  "KB5034441",
		"5034441":      "KB5034441",
		"KB123":        "", // too short
		"KB123456789":  "", // too long
		"KB50344a1":    "",
		"":             "",
		"KB5034441; x": "",
	}
	for in, want := range cases {
		if got := NormalizeKB(in); got != want {
			t.Errorf("NormalizeKB(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseDate(t *testing.T) {
	for in, want := range map[string]string{
		"20240315":   "2024-03-15", // registry InstallDate
		"2024-03-15": "2024-03-15", // WMI / ISO
		"03/15/2024": "2024-03-15", // SMBIOS BIOS date
	} {
		got := parseDate(in)
		if got == nil || got.Format("2006-01-02") != want {
			t.Errorf("parseDate(%q) = %v, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "15/03/2024", "yesterday", "19000101", "20240231"} {
		if got := parseDate(bad); got != nil {
			t.Errorf("parseDate(%q) = %v, want nil", bad, got)
		}
	}
}

func TestParseIP(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.5":    "10.0.0.5",
		"10.0.0.5/24": "10.0.0.5",
		"fe80::1%12":  "fe80::1",
		" ::1 ":       "::1",
	} {
		got, ok := parseIP(in)
		if !ok || got.String() != want {
			t.Errorf("parseIP(%q) = %v, %v, want %s", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "10.0.0", "not-an-ip"} {
		if _, ok := parseIP(bad); ok {
			t.Errorf("parseIP(%q) accepted", bad)
		}
	}
}

func TestClipKeepsValidUTF8(t *testing.T) {
	s := strings.Repeat("a", maxText-1) + "é" // é is 2 bytes and straddles the cut
	got := clip(s)
	if !utf8.ValidString(got) || len(got) > maxText {
		t.Fatalf("clip produced %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
	if nullable("   ") != nil {
		t.Fatal("nullable of blank should be nil")
	}
}
