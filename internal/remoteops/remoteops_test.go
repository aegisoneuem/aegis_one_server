package remoteops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"app.log":               "app.log",
		`C:\Windows\Temp\x.log`: "x.log",
		"../../etc/passwd":      "passwd",
		"bad name;rm -rf.txt":   "bad_name_rm_-rf.txt",
		"..":                    "file",
		"":                      "file",
		"résumé.pdf":            "r_sum_.pdf",
		"2_dup.txt":             "2_dup.txt",
	} {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUniquePath(t *testing.T) {
	dir := t.TempDir()
	abs, rel := uniquePath(dir, "uploads/d/c", "a.txt")
	if filepath.Base(abs) != "a.txt" || rel != "uploads/d/c/a.txt" {
		t.Fatalf("first: %s %s", abs, rel)
	}
	os.WriteFile(abs, nil, 0o600)
	abs, rel = uniquePath(dir, "uploads/d/c", "a.txt")
	if filepath.Base(abs) != "a-2.txt" || rel != "uploads/d/c/a-2.txt" {
		t.Fatalf("second: %s %s", abs, rel)
	}
}

func TestCheckPath(t *testing.T) {
	for _, ok := range []string{`C:\Logs\*.log`, "relative/dir", `\\server\share\f`} {
		if err := checkPath("p", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "   ", "a\nb", string(make([]byte, 1025))} {
		if err := checkPath("p", bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}
