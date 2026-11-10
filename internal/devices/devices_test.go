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
