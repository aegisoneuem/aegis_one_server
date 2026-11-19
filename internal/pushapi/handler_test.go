package pushapi

import (
	"net/url"
	"strings"
	"testing"
)

func TestPatchSpec(t *testing.T) {
	h := strings.Repeat("ab", 32)
	ok := []struct {
		typ string
		q   url.Values
	}{
		{"install_patch", url.Values{"kb": {" kb5034441 "}, "file_path": {"windows11.0-kb5034441-x64.msu"}, "expected_hash": {strings.ToUpper(h)}}},
		{"install_patch", url.Values{"kb": {"KB5034441"}, "file_path": {`C:\ProgramData\AegisOne\cache\x.CAB`}, "expected_hash": {h}, "hash_algorithm": {"SHA256"}}},
		{"stage_patch", url.Values{"kb": {"KB5034441"}, "expected_hash": {h}}},
		{"stage_patch", url.Values{"kb": {"KB5034441"}, "file_path": {"x.msu"}, "expected_hash": {h}}},
		{"uninstall_patch", url.Values{"kb": {"KB5034441"}}},
	}
	for _, c := range ok {
		spec, msg := patchSpec(c.typ, c.q)
		if msg != "" || spec == nil {
			t.Errorf("%s %v: rejected: %s", c.typ, c.q, msg)
			continue
		}
		if spec.Kb != "KB5034441" {
			t.Errorf("%s: kb %q", c.typ, spec.Kb)
		}
		if c.typ != "uninstall_patch" && (spec.ExpectedHash != h || spec.HashAlgorithm != "sha256") {
			t.Errorf("%s: hash %q algo %q", c.typ, spec.ExpectedHash, spec.HashAlgorithm)
		}
	}

	install := func(over url.Values) url.Values {
		q := url.Values{"kb": {"KB5034441"}, "file_path": {"x.msu"}, "expected_hash": {h}}
		for k, v := range over {
			if len(v) == 1 && v[0] == "" {
				delete(q, k)
			} else {
				q[k] = v
			}
		}
		return q
	}
	bad := map[string]struct {
		typ string
		q   url.Values
	}{
		"no kb":               {"install_patch", install(url.Values{"kb": {""}})},
		"junk kb":             {"install_patch", install(url.Values{"kb": {"KB1234-evil"}})},
		"kb too short":        {"uninstall_patch", url.Values{"kb": {"KB123"}}},
		"no hash":             {"install_patch", install(url.Values{"expected_hash": {""}})},
		"short hash":          {"install_patch", install(url.Values{"expected_hash": {"abc"}})},
		"sha512":              {"install_patch", install(url.Values{"hash_algorithm": {"sha512"}})},
		"no file_path":        {"install_patch", install(url.Values{"file_path": {""}})},
		"UNC path":            {"install_patch", install(url.Values{"file_path": {`\\attacker\share\x.msu`}})},
		"forward slashes":     {"install_patch", install(url.Values{"file_path": {`C:/cache/x.msu`}})},
		"traversal":           {"install_patch", install(url.Values{"file_path": {`C:\cache\..\..\Windows\x.msu`}})},
		"relative dir":        {"install_patch", install(url.Values{"file_path": {`cache\x.msu`}})},
		"not a patch file":    {"install_patch", install(url.Values{"file_path": {"x.exe"}})},
		"control char":        {"install_patch", install(url.Values{"file_path": {"x\x01.msu"}})},
		"too long":            {"install_patch", install(url.Values{"file_path": {strings.Repeat("a", 257) + ".msu"}})},
		"stage no hash":       {"stage_patch", url.Values{"kb": {"KB5034441"}}},
		"stage bad path":      {"stage_patch", url.Values{"kb": {"KB5034441"}, "expected_hash": {h}, "file_path": {`\\x\y.msu`}}},
		"uninstall with path": {"uninstall_patch", url.Values{"kb": {"KB5034441"}, "file_path": {"x.msu"}}},
	}
	for name, c := range bad {
		if spec, msg := patchSpec(c.typ, c.q); msg == "" || spec != nil {
			t.Errorf("%s: accepted %v", name, c.q)
		}
	}
}
