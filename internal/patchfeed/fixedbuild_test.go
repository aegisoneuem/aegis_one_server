package patchfeed

import "testing"

// Product names and builds as they appear in the 2026-Oct CVRF document.
func TestParseFixedBuild(t *testing.T) {
	tests := []struct {
		product, build string
		want           FixedBuild
		ok             bool
	}{
		{"Windows 11 Version 24H2 for x64-based Systems", "10.0.26100.9711",
			FixedBuild{OSKind: "client", Architecture: "x64", OSBuild: 26100, UBR: 9711}, true},
		{"Windows 11 Version 25H2 for ARM64-based Systems", "10.0.26200.9711",
			FixedBuild{OSKind: "client", Architecture: "arm64", OSBuild: 26200, UBR: 9711}, true},
		{"Windows 10 Version 22H2 for 32-bit Systems", "10.0.19045.6456",
			FixedBuild{OSKind: "client", Architecture: "x86", OSBuild: 19045, UBR: 6456}, true},
		{"windows 11 version 26H1 for x64-based Systems", "10.0.28000.3231",
			FixedBuild{OSKind: "client", Architecture: "x64", OSBuild: 28000, UBR: 3231}, true},
		// Same build number as 24H2, different release: must stay apart.
		{"Windows Server 2025", "10.0.26100.33650",
			FixedBuild{OSKind: "server", Architecture: "x64", OSBuild: 26100, UBR: 33650}, true},
		{"Windows Server 2025 (Server Core installation)", "10.0.26100.33650",
			FixedBuild{OSKind: "server", Architecture: "x64", OSBuild: 26100, UBR: 33650}, true},
		{"Windows Server 2025 Datacenter: Azure Edition (Hotpatch)", "10.0.26100.33700", FixedBuild{}, false},
		{"Microsoft .NET Framework 3.5 AND 4.8.1 on Windows 11 version 24H2", "4.8.9363.0", FixedBuild{}, false},
		{"HEVC Video Extensions from Device Manufacturer on Windows 11 Version 24H2 for x64-based Systems", "2.4.86.0", FixedBuild{}, false},
		{"Windows 11 Version 24H2 for x64-based Systems", "", FixedBuild{}, false},
		{"Windows 11 Version 24H2 for x64-based Systems", "10.0.26100", FixedBuild{}, false},
		{"Windows Server 2008 for Itanium-Based Systems Service Pack 2", "6.0.6003.23000", FixedBuild{}, false},
	}
	for _, tt := range tests {
		got, ok := parseFixedBuild(tt.product, tt.build)
		if ok != tt.ok {
			t.Errorf("parseFixedBuild(%q, %q) ok = %v, want %v", tt.product, tt.build, ok, tt.ok)
			continue
		}
		if !ok {
			continue
		}
		tt.want.Product = tt.product
		if got != tt.want {
			t.Errorf("parseFixedBuild(%q, %q) = %+v, want %+v", tt.product, tt.build, got, tt.want)
		}
	}
}

func TestAddFixedBuildOnePerProduct(t *testing.T) {
	rec := &KBRecord{}
	p := "Windows 11 Version 24H2 for x64-based Systems"
	rec.addFixedBuild(FixedBuild{Product: p, OSKind: "client", Architecture: "x64", OSBuild: 26100, UBR: 9700})
	rec.addFixedBuild(FixedBuild{Product: p, OSKind: "client", Architecture: "x64", OSBuild: 26100, UBR: 9711})
	rec.addFixedBuild(FixedBuild{Product: p, OSKind: "client", Architecture: "x64", OSBuild: 26100, UBR: 9711})
	if len(rec.FixedBuilds) != 1 || rec.FixedBuilds[0].UBR != 9711 {
		t.Fatalf("FixedBuilds = %+v, want one entry at UBR 9711", rec.FixedBuilds)
	}
}
