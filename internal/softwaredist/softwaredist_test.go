package softwaredist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMetaValidate(t *testing.T) {
	ok := Meta{Name: "7-Zip", Version: "24.08", InstallerType: "msi", ProductCode: "{23170F69-40C1-2702-2408-000001000000}"}
	tests := []struct {
		name    string
		meta    Meta
		file    string
		wantErr string
	}{
		{"valid msi", ok, "7z2408-x64.msi", ""},
		{"type is case-insensitive", Meta{Name: "a", Version: "1", InstallerType: " EXE "}, "setup.EXE", ""},
		{"script", Meta{Name: "fix", Version: "1", InstallerType: "ps1"}, "fix.ps1", ""},
		{"python", Meta{Name: "fix", Version: "1", InstallerType: "python"}, "fix.py", ""},
		{"no name", Meta{Version: "1", InstallerType: "msi"}, "a.msi", "name is required"},
		{"no version", Meta{Name: "a", InstallerType: "msi"}, "a.msi", "version is required"},
		{"command type refused", Meta{Name: "a", Version: "1", InstallerType: "command"}, "a.exe", "installer_type must be one of"},
		{"extension mismatch", Meta{Name: "a", Version: "1", InstallerType: "msi"}, "a.exe", "needs a .msi file"},
		{"bad product code", Meta{Name: "a", Version: "1", InstallerType: "msi", ProductCode: "23170F69"}, "a.msi", "product_code"},
		{"uninstall key path", Meta{Name: "a", Version: "1", InstallerType: "exe", UninstallKey: `SOFTWARE\x`}, "a.exe", "subkey name only"},
		{"control char", Meta{Name: "a\nb", Version: "1", InstallerType: "exe"}, "a.exe", "control characters"},
		{"timeout too big", Meta{Name: "a", Version: "1", InstallerType: "exe", TimeoutSeconds: 90000}, "a.exe", "timeout_seconds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.meta
			err := m.Validate(tt.file)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var ue *UserError
			if !errors.As(err, &ue) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want a UserError containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestMetaFromFields(t *testing.T) {
	m, err := metaFromFields(map[string]string{
		"name": "App", "version": "2.0", "installer_type": "exe", "silent_args": "/S",
		"success_exit_codes": "0, 1, 3010", "timeout_seconds": "600", "require_signature": "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.SuccessExitCodes, []int32{0, 1, 3010}) || m.TimeoutSeconds != 600 || !m.RequireSignature || m.SilentArgs != "/S" {
		t.Fatalf("meta = %+v", m)
	}
	for _, bad := range []map[string]string{{"timeout_seconds": "x"}, {"require_signature": "maybe"}, {"success_exit_codes": "0,a"}} {
		if _, err := metaFromFields(bad); err == nil {
			t.Errorf("metaFromFields(%v) accepted bad input", bad)
		}
	}
}

func TestIsScript(t *testing.T) {
	for typ, want := range map[string]bool{"msi": false, "exe": false, "ps1": true, "bat": true, "cmd": true, "python": true, "vbs": true} {
		if IsScript(typ) != want {
			t.Errorf("IsScript(%q) = %v", typ, !want)
		}
		if got := packageFormat(typ, false); (got == "script") != want {
			t.Errorf("packageFormat(%q) = %q", typ, got)
		}
	}
}

func TestSpec(t *testing.T) {
	p := &Package{
		ID: "11111111-2222-3333-4444-555555555555", Name: "7-Zip", Version: "24.08", InstallerType: "msi",
		SHA256: strings.Repeat("ab", 32), SilentArgs: "/qn", ProductCode: "{23170F69-40C1-2702-2408-000001000000}",
		SuccessExitCodes: []int32{1}, TimeoutSeconds: 600, RequireSignature: true, storageName: "software/x.msi",
	}
	s := Spec(p, "install", SpecOptions{})
	if s.GetContentId() != p.ID || s.GetPackageId() != p.ID || s.GetAction() != "install" {
		t.Errorf("ids/action wrong: %+v", s)
	}
	if s.GetExpectedHash() != p.SHA256 || s.GetHashAlgorithm() != "sha256" {
		t.Errorf("hash not pinned: %+v", s)
	}
	// The agent names the fetched file from file_path's extension.
	if s.GetFilePath() != p.ID+".msi" {
		t.Errorf("file_path = %q", s.GetFilePath())
	}
	if !s.GetRequireSignature() || s.GetTimeoutSeconds() != 600 || s.GetProductCode() != p.ProductCode {
		t.Errorf("options not carried: %+v", s)
	}

	// Uninstall of an MSI with a ProductCode: no file, so the agent runs
	// msiexec /x {ProductCode} instead of re-running the installer.
	u := Spec(p, "uninstall", SpecOptions{})
	if u.GetFilePath() != "" || u.GetContentId() != "" || u.GetExpectedHash() != "" || u.GetProductCode() != p.ProductCode {
		t.Errorf("msi uninstall not fileless: %+v", u)
	}
}

func TestFilelessUninstall(t *testing.T) {
	pc := "{23170F69-40C1-2702-2408-000001000000}"
	cases := []struct {
		name string
		p    Package
		want bool
	}{
		{"msi by product code", Package{InstallerType: "msi", ProductCode: pc}, true},
		{"msi without product code", Package{InstallerType: "msi", DisplayName: "7-Zip"}, false},
		{"exe by uninstall key", Package{InstallerType: "exe", UninstallKey: "7-Zip"}, true},
		{"exe by display name", Package{InstallerType: "exe", DisplayName: "Notepad++"}, true},
		{"exe by product code only", Package{InstallerType: "exe", ProductCode: pc}, false},
		{"exe, nothing to find it by", Package{InstallerType: "exe"}, false},
		{"script", Package{InstallerType: "ps1", DisplayName: "Tool"}, false},
		{"msix", Package{InstallerType: "msix", UninstallKey: "Pkg_1.0.0.0_x64__abc"}, false},
		{"inf", Package{InstallerType: "inf", DisplayName: "Driver"}, false},
		{"bundle", Package{InstallerType: "msi", ProductCode: pc, IsBundle: true}, false},
		{"detection rules", Package{InstallerType: "exe", Detection: &Detection{}}, false},
		{"steps", Package{InstallerType: "exe", DisplayName: "X", Steps: &Steps{Before: []Step{{}}}}, false},
	}
	for _, c := range cases {
		if got := FilelessUninstall(&c.p); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// An exe uninstall keeps nothing of the installer file; install still pins it.
	p := &Package{ID: "11111111-2222-3333-4444-555555555555", InstallerType: "exe", DisplayName: "Notepad++", SHA256: strings.Repeat("cd", 32)}
	if u := Spec(p, "uninstall", SpecOptions{}); u.GetFilePath() != "" || u.GetExpectedHash() != "" || u.GetDisplayName() != "Notepad++" {
		t.Errorf("exe uninstall spec: %+v", u)
	}
	if i := Spec(p, "install", SpecOptions{}); i.GetFilePath() == "" || i.GetExpectedHash() != p.SHA256 {
		t.Errorf("exe install spec lost its file: %+v", i)
	}
}

func TestDedupe(t *testing.T) {
	got := dedupe([]string{" a", "b", "a", "", "  ", "c", "b"})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("dedupe = %v", got)
	}
}

func TestStage(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(nil, dir, 10, slog.New(slog.NewTextHandler(io.Discard, nil)))

	data := []byte("0123456789")
	st, err := s.Stage(`C:\Users\x\setup.msi`, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if st.FileName != "setup.msi" || st.SizeBytes != 10 || st.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("staged = %+v", st)
	}
	s.Discard(st)
	if _, err := os.Stat(st.tmp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp file not removed: %v", err)
	}

	var ue *UserError
	if _, err := s.Stage("big.msi", bytes.NewReader(make([]byte, 11))); !errors.As(err, &ue) {
		t.Fatalf("over-cap upload: err = %v, want UserError", err)
	}
	if _, err := s.Stage("empty.msi", bytes.NewReader(nil)); !errors.As(err, &ue) {
		t.Fatalf("empty upload: err = %v, want UserError", err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "software", "*"))
	if len(left) != 0 {
		t.Fatalf("leftover files after refused uploads: %v", left)
	}
}
