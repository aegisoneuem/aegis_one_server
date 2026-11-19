package remoteops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// The manifest a source agent returns from pack is relayed, signed, to every
// destination: it must be checked here, not only on the agents.
func TestValidEntries(t *testing.T) {
	h := strings.Repeat("0a", 32)
	file := func(name string, size int64) entry {
		return entry{Source: `C:\Share\` + name, Name: name, Size: size, SHA256: h}
	}
	dir := func(name string) entry { return entry{Source: `C:\Share\` + name, Name: name, Directory: true} }
	raw := func(list ...entry) json.RawMessage {
		b, _ := json.Marshal(list)
		return b
	}

	out, err := validEntries(raw(dir("docs"), file(`docs\a.txt`, 5), file("b.txt", 0)))
	if err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
	var back []entry
	if json.Unmarshal(out, &back) != nil || len(back) != 3 || back[1].Name != `docs\a.txt` || back[1].SHA256 != h {
		t.Fatalf("canonical form: %s", out)
	}
	// Unknown fields are dropped, not relayed.
	loose := json.RawMessage(`[{"source":"C:\\x\\a.txt","name":"a.txt","size":1,"sha256":"` + h + `","mode":"0777","extra":{"x":1}}]`)
	if out, err := validEntries(loose); err != nil || strings.Contains(string(out), "extra") || strings.Contains(string(out), "mode") {
		t.Errorf("unknown fields: %s %v", out, err)
	}

	big := make([]entry, maxTransferEntries+1)
	for i := range big {
		big[i] = file("f"+strconv.Itoa(i)+".txt", 1)
	}
	bad := map[string]json.RawMessage{
		"not an array":        json.RawMessage(`{"name":"a"}`),
		"empty":               json.RawMessage(`[]`),
		"too many":            raw(big...),
		"absolute name":       raw(file(`\Windows\System32\x.dll`, 1)),
		"drive name":          raw(entry{Source: `C:\x`, Name: `C:\x`, Size: 1, SHA256: h}),
		"traversal":           raw(file(`..\..\Windows\x.dll`, 1)),
		"dot segment":         raw(file(`a\.\b.txt`, 1)),
		"empty segment":       raw(file(`a\\b.txt`, 1)),
		"reserved char":       raw(file(`a?.txt`, 1)),
		"trailing dot":        raw(file(`a.`, 1)),
		"control char":        raw(file("a\x01.txt", 1)),
		"long name":           raw(file(strings.Repeat("a", 1025), 1)),
		"duplicate name":      raw(file("a.txt", 1), file("A.TXT", 1)),
		"no source":           raw(entry{Name: "a.txt", Size: 1, SHA256: h}),
		"negative size":       raw(file("a.txt", -1)),
		"over total":          raw(file("a.txt", maxTransferBytes), file("b.txt", 1)),
		"file without digest": raw(entry{Source: `C:\x\a`, Name: "a", Size: 1}),
		"upper-case digest":   raw(entry{Source: `C:\x\a`, Name: "a", Size: 1, SHA256: strings.ToUpper(h)}),
		"short digest":        raw(entry{Source: `C:\x\a`, Name: "a", Size: 1, SHA256: "abc"}),
		"directory with size": raw(entry{Source: `C:\x\d`, Name: "d", Directory: true, Size: 3}),
		"oversized manifest":  json.RawMessage("[" + strings.Repeat(" ", maxManifestBytes) + "]"),
	}
	for name, r := range bad {
		if _, err := validEntries(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
