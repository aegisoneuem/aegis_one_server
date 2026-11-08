package patchdiff

import "testing"

func TestDecide(t *testing.T) {
	cases := []struct {
		name                   string
		deviceUBR, latestUBR   int
		kbInstalled, pendingRB bool
		want                   string
	}{
		{"behind", 4652, 4890, false, false, "missing"},
		{"at the fixed build", 4890, 4890, false, false, "installed"},
		{"past it (newer preview)", 4900, 4890, false, false, "installed"},
		{"installed, waiting for reboot", 4652, 4890, true, true, "pending_reboot"},
		// The build is authoritative: a KB in the installed set without a
		// pending reboot and an old UBR is still missing.
		{"kb listed but build not moved, no reboot pending", 4652, 4890, true, false, "missing"},
		{"reboot pending for something else", 4652, 4890, false, true, "missing"},
		// Being at the build wins over a stale pending-reboot flag.
		{"at build with stale reboot flag", 4890, 4890, true, true, "installed"},
	}
	for _, c := range cases {
		if got := Decide(c.deviceUBR, c.latestUBR, c.kbInstalled, c.pendingRB); got != c.want {
			t.Errorf("%s: Decide = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestClipUTF8(t *testing.T) {
	if got := clip("ab€", 3); got != "ab" { // € is 3 bytes; cutting at 3 would split it
		t.Fatalf("clip = %q", got)
	}
	if got := clip("  ok  ", 10); got != "ok" {
		t.Fatalf("clip = %q", got)
	}
}
