package ingest

import (
	"strings"
	"testing"

	aegisonev1 "aegis-one/gen/aegisone/v1"
)

// Only a well-formed KB number may create or match a fleet-wide catalog row.
func TestFirstKBStrict(t *testing.T) {
	cases := map[string]string{
		"KB5034441":      "KB5034441",
		"kb5034441":      "KB5034441",
		" 5034441 ":      "KB5034441",
		"KB5055555":      "KB5055555",
		"":               "",
		"KB":             "",
		"KB12":           "",
		"KB123456789":    "",
		"KB5034441A":     "",
		"KB5034441;DROP": "",
		"<script>":       "",
		"KB 5034441":     "",
	}
	for in, want := range cases {
		m := &aegisonev1.MissingUpdate{KbArticleIds: []string{in}}
		if got := firstKB(m); got != want {
			t.Errorf("firstKB(%q) = %q, want %q", in, got, want)
		}
	}
	// The first well-formed id wins, junk before it is skipped.
	m := &aegisonev1.MissingUpdate{KbArticleIds: []string{"junk", "KB5034441", "KB5034442"}}
	if got := firstKB(m); got != "KB5034441" {
		t.Errorf("firstKB = %q", got)
	}
}

// An agent-supplied KB article link is kept only when it is an https link to a
// Microsoft documentation host; everything else is dropped (stored as NULL).
func TestAgentArticleURL(t *testing.T) {
	keep := []string{
		"https://support.microsoft.com/help/5034441",
		"https://support.microsoft.com/en-us/topic/kb5034441-abc?x=1",
		"https://catalog.update.microsoft.com/Search.aspx?q=KB5034441",
		"https://www.catalog.update.microsoft.com/Search.aspx?q=KB5034441",
		"https://learn.microsoft.com/windows/release-health/",
		"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1",
		"https://go.microsoft.com/fwlink/?LinkId=2165345",
		"  https://support.microsoft.com/help/5034441  ",
	}
	for _, u := range keep {
		if got := agentArticleURL(u); got != strings.TrimSpace(u) {
			t.Errorf("agentArticleURL(%q) = %q, want kept", u, got)
		}
	}
	drop := []string{
		"",
		"http://support.microsoft.com/help/5034441",               // not https
		"https://attacker.example/kb5034441",                      // not Microsoft
		"https://support.microsoft.com.attacker.example/x",        // suffix trick
		"https://attacker.example/support.microsoft.com",          // host in path
		"https://support.microsoft.com@attacker.example/x",        // userinfo trick
		"https://user:pw@support.microsoft.com/x",                 // credentials
		"javascript:alert(1)",                                     // not a URL scheme we render
		"https://support.microsoft.com/help/5034441 trailing",     // whitespace inside
		"https://support.microsoft.com/help/\x01",                 // control char
		"https://support.microsoft.com/помощь",                    // non-ASCII (would need encoding)
		"https://" + strings.Repeat("a", 1100) + ".microsoft.com", // too long
		"//support.microsoft.com/help/5034441",                    // scheme-relative
		"support.microsoft.com/help/5034441",                      // no scheme
	}
	for _, u := range drop {
		if got := agentArticleURL(u); got != "" {
			t.Errorf("agentArticleURL(%q) = %q, want dropped", u, got)
		}
	}
}
