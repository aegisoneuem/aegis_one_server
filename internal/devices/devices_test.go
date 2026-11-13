package devices

import (
	"strings"
	"testing"
)

func TestValidateRetire(t *testing.T) {
	ok := RetireRequest{DeviceIDs: []string{" a ", "a", "b", ""}, Reason: "  laptop returned  "}
	if err := validateRetire(&ok); err != nil {
		t.Fatal(err)
	}
	if len(ok.DeviceIDs) != 2 || ok.Reason != "laptop returned" {
		t.Errorf("not normalized: %+v", ok)
	}
	bad := []RetireRequest{
		{DeviceIDs: []string{"a"}},
		{DeviceIDs: []string{"a"}, Reason: "   "},
		{DeviceIDs: []string{"a"}, Reason: "line1\nline2"},
		{DeviceIDs: []string{"a"}, Reason: strings.Repeat("x", MaxReason+1)},
		{DeviceIDs: nil, Reason: "x"},
		{DeviceIDs: []string{" ", ""}, Reason: "x"},
		{DeviceIDs: make([]string, 0), Reason: "x"},
	}
	many := RetireRequest{Reason: "x"}
	for i := 0; i <= MaxRetire; i++ {
		many.DeviceIDs = append(many.DeviceIDs, strings.Repeat("d", 3)+string(rune('a'+i%26))+strings.Repeat("0", i/26))
	}
	bad = append(bad, many)
	for _, r := range bad {
		if err := validateRetire(&r); err == nil {
			t.Errorf("accepted: reason=%q devices=%d", r.Reason, len(r.DeviceIDs))
		}
	}
	if r := (RetireRequest{DeviceIDs: []string{"a"}, Reason: strings.Repeat("é", MaxReason)}); validateRetire(&r) != nil {
		t.Error("reason length should count characters, not bytes")
	}
}

func TestCursor(t *testing.T) {
	c := cursor{Hostname: "HOST-01", DeviceID: "58a3dbb3-f418-44f4-81ea-5e1dc5a92668"}
	got, err := decodeCursor(c.encode())
	if err != nil || got != c {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, s := range []string{"", "!!!", "e30", "bm90LWpzb24"} { // "", junk, "{}", "not-json"
		if _, err := decodeCursor(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestEscapeLike(t *testing.T) {
	if got := escapeLike(`a%b_c\d`); got != `a\%b\_c\\d` {
		t.Errorf("got %q", got)
	}
}

func TestStatesHaveFilters(t *testing.T) {
	for _, s := range States {
		if stateWhere[s] == "" {
			t.Errorf("state %q has no filter", s)
		}
		if !strings.Contains(stateSQL, "'"+s+"'") {
			t.Errorf("state %q missing from stateSQL", s)
		}
	}
}

func TestUUIDLike(t *testing.T) {
	for s, want := range map[string]bool{
		"58a3dbb3-f418-44f4-81ea-5e1dc5a92668": true,
		"58A3DBB3-F418-44F4-81EA-5E1DC5A92668": true,
		"58a3dbb3f41844f481ea5e1dc5a92668":     false,
		"58a3dbb3-f418-44f4-81ea-5e1dc5a9266z": false,
		"'; DROP TABLE devices; --":            false,
		"":                                     false,
	} {
		if got := uuidLike(s); got != want {
			t.Errorf("uuidLike(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestStateFilters(t *testing.T) {
	for _, s := range append(States, "stale_alert") {
		if stateWhere[s] == "" {
			t.Errorf("state %q has no filter", s)
		}
	}
}
