package patchbaseline

import (
	"reflect"
	"testing"
)

func testIndex() Index {
	ix := Index{}
	ix.Set("client", "x64", 26100, Latest{KB: "KB5127648", UBR: 9711})
	ix.Set("server", "x64", 26100, Latest{KB: "KB5126646", UBR: 33650})
	return ix
}

func intp(n int) *int { return &n }

func TestFor(t *testing.T) {
	ix := testIndex()
	tests := []struct {
		name    string
		dev     Device
		ok      bool
		build   string
		wantKBs []string
	}{
		{"behind", DeviceFrom("Windows 11 Pro", "26100", intp(4652), "x64"), true, "26100.4652", []string{"KB5127648"}},
		{"current", DeviceFrom("Windows 11 Pro", "26100", intp(9711), "x64"), true, "26100.9711", []string{}},
		{"ahead (preview build)", DeviceFrom("Windows 11 Pro", "26100", intp(9800), "x64"), true, "26100.9800", []string{}},
		// Server 2025 shares build 26100 but must get the server KB.
		{"server", DeviceFrom("Windows Server 2025 Datacenter", "26100", intp(32000), "x64"), true, "26100.32000", []string{"KB5126646"}},
		{"unknown build family", DeviceFrom("Windows 11 Pro", "26200", intp(1000), "x64"), false, "", nil},
		{"unknown arch", DeviceFrom("Windows 11 Pro", "26100", intp(4652), ""), false, "", nil},
		{"no UBR", DeviceFrom("Windows 11 Pro", "26100", nil, "x64"), false, "", nil},
		{"no build", DeviceFrom("", "", nil, ""), false, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bl, ok := ix.For(tt.dev)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if bl.GetBuild() != tt.build {
				t.Errorf("build = %q, want %q", bl.GetBuild(), tt.build)
			}
			if !reflect.DeepEqual(bl.GetLatestKbs(), tt.wantKBs) {
				t.Errorf("latest_kbs = %v, want %v", bl.GetLatestKbs(), tt.wantKBs)
			}
		})
	}
}

func TestKeyIgnoresIssuedAt(t *testing.T) {
	ix := testIndex()
	a, _ := ix.For(DeviceFrom("Windows 11 Pro", "26100", intp(4652), "x64"))
	b, _ := ix.For(DeviceFrom("Windows 11 Pro", "26100", intp(4652), "x64"))
	a.IssuedAt, b.IssuedAt = 1, 2
	if Key(a) != Key(b) {
		t.Fatalf("Key differs only by issued_at: %q vs %q", Key(a), Key(b))
	}
	c, _ := ix.For(DeviceFrom("Windows 11 Pro", "26100", intp(9711), "x64"))
	if Key(a) == Key(c) {
		t.Fatalf("Key same for different builds: %q", Key(a))
	}
}
