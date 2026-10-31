package ingest

import "testing"

func TestSplitBuild(t *testing.T) {
	tests := []struct {
		in    string
		build string
		ubr   int
	}{
		{"26100.4652", "26100", 4652},
		{" 26200.9457 ", "26200", 9457},
		{"26100", "26100", -1},
		{"26100.x", "", -1},
		{"", "", -1},
		{"abc.12", "", -1},
	}
	for _, tt := range tests {
		b, u := SplitBuild(tt.in)
		if b != tt.build || u != tt.ubr {
			t.Errorf("SplitBuild(%q) = %q, %d; want %q, %d", tt.in, b, u, tt.build, tt.ubr)
		}
	}
}

func TestNormalizeArch(t *testing.T) {
	for in, want := range map[string]string{"amd64": "x64", "ARM64": "arm64", "x86": "x86", "ia64": "", "": ""} {
		if got := NormalizeArch(in); got != want {
			t.Errorf("NormalizeArch(%q) = %q, want %q", in, got, want)
		}
	}
}
