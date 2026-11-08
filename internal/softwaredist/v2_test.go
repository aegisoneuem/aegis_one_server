package softwaredist

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	aegisonev1 "aegis-one/gen/aegisone/v1"
)

// makeBundle builds a ZIP with the given files and a manifest; tamper lets a
// test corrupt the manifest.
func makeBundle(t *testing.T, files map[string]string, tamper func(*manifest)) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var m manifest
	m.Version = 1
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
		sum := sha256.Sum256([]byte(body))
		m.Files = append(m.Files, struct {
			Path      string `json:"path"`
			Size      int64  `json:"size"`
			SHA256    string `json:"sha256"`
			Directory bool   `json:"directory"`
		}{Path: name, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
	}
	if tamper != nil {
		tamper(&m)
	}
	mb, _ := json.Marshal(m)
	w, _ := zw.Create(bundleManifest)
	w.Write(mb)
	zw.Close()
	return bytes.NewReader(buf.Bytes())
}

func TestValidateBundle(t *testing.T) {
	ok := makeBundle(t, map[string]string{"setup.msi": "MSI", "config/app.ini": "x=1"}, nil)
	info, err := ValidateBundle(ok, ok.Size())
	if err != nil || info.Members != 2 || !info.Paths["config/app.ini"] {
		t.Fatalf("valid bundle: %+v %v", info, err)
	}
	cases := map[string]*bytes.Reader{
		"hash mismatch": makeBundle(t, map[string]string{"a.exe": "A"}, func(m *manifest) { m.Files[0].SHA256 = strings.Repeat("0", 64) }),
		"size mismatch": makeBundle(t, map[string]string{"a.exe": "A"}, func(m *manifest) { m.Files[0].Size = 99 }),
		"unlisted":      makeBundle(t, map[string]string{"a.exe": "A", "b.dll": "B"}, func(m *manifest) { m.Files = m.Files[:1] }),
		"traversal":     makeBundle(t, map[string]string{"../evil.exe": "E"}, nil),
		"reserved":      makeBundle(t, map[string]string{"con.txt": "E"}, nil),
		"bad version":   makeBundle(t, map[string]string{"a.exe": "A"}, func(m *manifest) { m.Version = 2 }),
	}
	for name, r := range cases {
		if _, err := ValidateBundle(r, r.Size()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	notZip := bytes.NewReader([]byte("not a zip"))
	if _, err := ValidateBundle(notZip, notZip.Size()); err == nil {
		t.Error("non-zip accepted")
	}
}

func TestStepsValidate(t *testing.T) {
	good := &Steps{Before: []Step{{Name: "stop svc", Command: `cmd.exe /D /C sc stop foo`}},
		Rollback: []Step{{Name: "start svc", Command: "cmd.exe", Arguments: "/D /C sc start foo", TimeoutSeconds: 60}}}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	many := &Steps{}
	for i := 0; i < 9; i++ {
		many.After = append(many.After, Step{Name: "s", Command: "x"})
	}
	for name, s := range map[string]*Steps{
		"no name":      {Before: []Step{{Command: "x"}}},
		"multiline":    {Before: []Step{{Name: "a\nb", Command: "x"}}},
		"no command":   {Before: []Step{{Name: "a"}}},
		"long timeout": {Before: []Step{{Name: "a", Command: "x", TimeoutSeconds: 3601}}},
		"too many":     many,
	} {
		if err := s.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDetectionValidate(t *testing.T) {
	good := &Detection{Mode: "ANY", Rules: []Rule{
		{Kind: "file_version", Path: `C:\Program Files\App\app.exe`, MinimumVersion: "24.8.0.0"},
		{Kind: "registry_value", Hive: "hklm", Key: `SOFTWARE\App`, ValueName: "Ver", ValueType: "dword", ExpectedValue: "5", View: "64"},
	}}
	if err := good.validate(); err != nil || good.Mode != "any" || good.Rules[1].Hive != "HKLM" {
		t.Fatalf("good: %v %+v", err, good)
	}
	for name, d := range map[string]*Detection{
		"no rules":     {},
		"bad kind":     {Rules: []Rule{{Kind: "wmi"}}},
		"bad version":  {Rules: []Rule{{Kind: "file_version", Path: "x", MinimumVersion: "1.70000"}}},
		"bad hive":     {Rules: []Rule{{Kind: "registry_key", Hive: "HKU", Key: "k"}}},
		"bad view":     {Rules: []Rule{{Kind: "registry_key", Hive: "HKLM", Key: "k", View: "86"}}},
		"dword text":   {Rules: []Rule{{Kind: "registry_value", Hive: "HKLM", Key: "k", ValueType: "dword", ExpectedValue: "abc"}}},
		"package_dir":  {Rules: []Rule{{Kind: "file_exists", Path: "${package_dir}\\a"}}},
		"var in key":   {Rules: []Rule{{Kind: "registry_key", Hive: "HKLM", Key: "${x}"}}},
		"bad mode":     {Mode: "most", Rules: []Rule{{Kind: "file_exists", Path: "x"}}},
		"missing path": {Rules: []Rule{{Kind: "file_exists"}}},
	} {
		if err := d.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateSecrets(t *testing.T) {
	params := map[string]string{"Mode": "silent"}
	if err := validateSecrets(map[string]string{"LicenseKey": "ABCD-1234"}, "P@ssw0rd!", params, []string{"/qn"}); err != nil {
		t.Fatal(err)
	}
	if err := validateSecrets(map[string]string{"LicenseKey": "ABCD-1234"}, "", params, []string{"/qn KEY=ABCD-1234"}); err == nil {
		t.Error("secret value in silent_args accepted")
	}
	if err := validateSecrets(map[string]string{"LicenseKey": "ABCD-1234"}, "", params, []string{"KEY=${LicenseKey}"}); err == nil {
		t.Error("${secret} placeholder in public text accepted")
	}
	if err := validateSecrets(nil, "P@ssw0rd!", params, []string{"/user admin /pass P@ssw0rd!"}); err == nil {
		t.Error("password in public text accepted")
	}
	if err := validateSecrets(map[string]string{"mode": "x"}, "", params, nil); err == nil {
		t.Error("secret name colliding with a parameter accepted")
	}
	if err := validateSecrets(map[string]string{"1bad": "x"}, "", nil, nil); err == nil {
		t.Error("bad secret name accepted")
	}
	if err := validateSecrets(map[string]string{"Big": strings.Repeat("x", 70<<10)}, "", nil, nil); err == nil {
		t.Error("oversize secrets accepted")
	}
}

func TestValidateDestination(t *testing.T) {
	for _, ok := range [][2]string{{"", ""}, {"", "always"}, {`C:\Aegis\pkg`, "retain"}, {`D:\x`, ""}} {
		if err := validateDestination(ok[0], ok[1]); err != nil {
			t.Errorf("%q/%q: %v", ok[0], ok[1], err)
		}
	}
	for _, bad := range [][2]string{{"", "retain"}, {`\\server\share`, ""}, {`relative\path`, ""}, {`C:\a\..\b`, ""}, {`C:\a\con`, ""}, {`C:\a`, "keep"}} {
		if err := validateDestination(bad[0], bad[1]); err == nil {
			t.Errorf("%q/%q: accepted", bad[0], bad[1])
		}
	}
}

func TestExecutionValidate(t *testing.T) {
	sid := uint32(2)
	for _, e := range []Execution{{}, {Mode: "logged_in_user", SessionID: &sid}, {Mode: "specified_account", Username: "svc", Domain: ".", Password: "x", DetectionScope: "user"}} {
		if err := e.validate(); err != nil {
			t.Errorf("%+v: %v", e, err)
		}
	}
	for _, e := range []Execution{
		{Mode: "system", Username: "x"},
		{Mode: "system", DetectionScope: "user"},
		{Mode: "logged_in_user", Password: "x"},
		{Mode: "specified_account", Username: "svc"},
		{Mode: "specified_account", Username: "svc", Password: "x", SessionID: &sid},
		{Mode: "root"},
	} {
		if err := e.validate(); err == nil {
			t.Errorf("%+v: accepted", e)
		}
	}
}

func TestCommandType(t *testing.T) {
	cases := []struct {
		s    *aegisonev1.SoftwareDeploySpec
		want string
	}{
		{&aegisonev1.SoftwareDeploySpec{}, "software_deploy"},
		{&aegisonev1.SoftwareDeploySpec{Execution: &aegisonev1.SoftwareExecution{Mode: "system"}}, "software_deploy_v2"},
		{&aegisonev1.SoftwareDeploySpec{SecureParameters: map[string]string{"A": "b"}}, "software_deploy_v2"},
		{&aegisonev1.SoftwareDeploySpec{Bundle: &aegisonev1.SoftwareBundle{}}, "software_deploy_bundle"},
		{&aegisonev1.SoftwareDeploySpec{Bundle: &aegisonev1.SoftwareBundle{}, Steps: &aegisonev1.SoftwareDeploymentSteps{}}, "software_deploy_workflow"},
		{&aegisonev1.SoftwareDeploySpec{Steps: &aegisonev1.SoftwareDeploymentSteps{}, Detection: &aegisonev1.SoftwareDetection{}}, "software_deploy_detect"},
	}
	for _, c := range cases {
		if got := CommandType(c.s); got != c.want {
			t.Errorf("CommandType = %s, want %s", got, c.want)
		}
	}
}

func TestMetaValidateBundle(t *testing.T) {
	m := Meta{Name: "App", Version: "1", InstallerType: "msi", BundleEntryPoint: "setup/app.msi"}
	if err := m.Validate("app.zip"); err != nil {
		t.Fatal(err)
	}
	m = Meta{Name: "App", Version: "1", BundleCommand: `cmd.exe /D /C install.cmd`}
	if err := m.Validate("app.zip"); err != nil || m.InstallerType != "command" {
		t.Fatalf("command bundle: %v %q", err, m.InstallerType)
	}
	for name, m := range map[string]Meta{
		"both":            {Name: "A", Version: "1", InstallerType: "msi", BundleEntryPoint: "a.msi", BundleCommand: "x"},
		"neither":         {Name: "A", Version: "1", InstallerType: "msi"},
		"wrong entry ext": {Name: "A", Version: "1", InstallerType: "msi", BundleEntryPoint: "a.exe"},
		"steps no bundle": {Name: "A", Version: "1", InstallerType: "msi", Steps: &Steps{Before: []Step{{Name: "a", Command: "x"}}}},
		"detection mix":   {Name: "A", Version: "1", InstallerType: "msi", BundleEntryPoint: "a.msi", ProductCode: "{23170F69-40C1-2702-2408-000001000000}", Detection: &Detection{Rules: []Rule{{Kind: "file_exists", Path: "x"}}}},
	} {
		if err := m.Validate("a.zip"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	inf := Meta{Name: "Drv", Version: "1", InstallerType: "inf"}
	if err := inf.Validate("drv.inf"); err != nil {
		t.Fatal(err)
	}
	if err := (&Meta{Name: "A", Version: "1", InstallerType: "msi", BundleCommand: "x"}).Validate("a.msi"); err == nil {
		t.Error("bundle fields on a non-zip accepted")
	}
}
