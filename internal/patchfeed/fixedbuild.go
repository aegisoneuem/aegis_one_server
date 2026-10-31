package patchfeed

import (
	"strconv"
	"strings"
)

// FixedBuild is the OS build one KB brings one Windows product to, from MSRC's
// Remediations[].FixedBuild. Only Windows OS products are kept; .NET, codecs
// and the like carry their own version numbers there, not an OS build.
type FixedBuild struct {
	Product      string
	OSKind       string // client | server
	Architecture string // x86 | x64 | arm64
	OSBuild      int    // 26100
	UBR          int    // 9711
}

// parseFixedBuild turns one (product, "10.0.26100.9711") pair into a
// FixedBuild, or reports false when it isn't a Windows OS build.
func parseFixedBuild(product, fixedBuild string) (FixedBuild, bool) {
	p := strings.ToLower(product)
	if !strings.HasPrefix(p, "windows 10") && !strings.HasPrefix(p, "windows 11") && !strings.HasPrefix(p, "windows server") {
		return FixedBuild{}, false
	}
	// Hotpatch devices follow their own UBR series; a hotpatch KB is not the
	// baseline for a regular device on the same build.
	if strings.Contains(p, "hotpatch") {
		return FixedBuild{}, false
	}
	parts := strings.Split(strings.TrimSpace(fixedBuild), ".")
	if len(parts) != 4 || parts[0] != "10" || parts[1] != "0" {
		return FixedBuild{}, false
	}
	build, err1 := strconv.Atoi(parts[2])
	ubr, err2 := strconv.Atoi(parts[3])
	if err1 != nil || err2 != nil || build <= 0 || ubr < 0 {
		return FixedBuild{}, false
	}

	fb := FixedBuild{Product: product, OSKind: "client", OSBuild: build, UBR: ubr}
	if strings.HasPrefix(p, "windows server") {
		fb.OSKind = "server"
	}
	switch {
	case strings.Contains(p, "arm64"):
		fb.Architecture = "arm64"
	case strings.Contains(p, "x64"):
		fb.Architecture = "x64"
	case strings.Contains(p, "32-bit"):
		fb.Architecture = "x86"
	case fb.OSKind == "server" && !strings.Contains(p, "itanium"):
		// Server products from 2016 on name no architecture: they are x64 only.
		fb.Architecture = "x64"
	default:
		return FixedBuild{}, false
	}
	return fb, true
}
