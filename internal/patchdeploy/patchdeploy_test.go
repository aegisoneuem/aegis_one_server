package patchdeploy

import "testing"

func TestArchMatches(t *testing.T) {
	cases := []struct {
		name, arch string
		want       bool
	}{
		{"windows11.0-kb5066835-x64_1a2b3c.msu", "x64", true},
		{"windows11.0-kb5066835-arm64_1a2b3c.msu", "arm64", true},
		{"windows11.0-kb5066835-arm64_1a2b3c.msu", "x64", false},
		{"Windows10.0-KB5066791-X86_aa.cab", "x86", true},
		{"windows10.0-kb5066791-x86_aa.cab", "x64", false},
		{"windows11.0-kb5066835-x64.msu", "x64", true},
		{"anything.msu", "", false},
	}
	for _, c := range cases {
		if got := ArchMatches(c.name, c.arch); got != c.want {
			t.Errorf("ArchMatches(%q, %q) = %v, want %v", c.name, c.arch, got, c.want)
		}
	}
}
