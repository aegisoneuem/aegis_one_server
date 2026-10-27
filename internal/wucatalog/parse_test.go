package wucatalog

import (
	"strings"
	"testing"
)

// Shape copied from the 2026-10 wsusscn2.cab: bundle 93 (KB5066835, what a
// device reports) with child 94 carrying the payload, which mixes the LCU and
// checkpoint .msu files with WU-only delivery pieces.
const fixture = `<?xml version="1.0" encoding="utf-8"?>
<OfflineSyncPackage xmlns="http://schemas.microsoft.com/msus/2004/02/OfflineSync">
<Updates>
<Update UpdateId="0C012F79-AA29-4982-AA6D-F1C1058D25BA" RevisionNumber="100" RevisionId="93" IsBundle="true">
  <Prerequisites><UpdateId Id="13c46d99-e6e6-4b68-b83d-33d73910d025" /></Prerequisites>
</Update>
<Update UpdateId="0a9269d1-df26-4ba0-bb32-bfd66bf757d6" RevisionNumber="100" RevisionId="94" IsLeaf="true">
  <PayloadFiles>
    <File Id="Lxk7" /><File Id="lTRJ" /><File Id="A4UC" /><File Id="srVq" /><File Id="cb0W" /><File Id="PFMc" />
  </PayloadFiles>
  <BundledBy><Revision Id="93" /></BundledBy>
</Update>
<Update UpdateId="11111111-1111-1111-1111-111111111111" RevisionId="200">
  <PayloadFiles><File Id="oldc" /><File Id="nope" /></PayloadFiles>
</Update>
</Updates>
<FileLocations>
<FileLocation Id="Lxk7" Url="http://dl.delivery.mp.microsoft.com/x/public/windows11.0-kb5066835-x64_2f19.msu" />
<FileLocation Id="lTRJ" Url="http://dl.delivery.mp.microsoft.com/x/public/windows11.0-kb5043080-x64_9534.msu" />
<FileLocation Id="A4UC" Url="http://dl.delivery.mp.microsoft.com/x/public/windows11.0-kb5067039-x64-baseless_0385.cab" />
<FileLocation Id="srVq" Url="http://dl.delivery.mp.microsoft.com/x/public/ssu-26100.6893-x64-express_b2b5.cab" />
<FileLocation Id="cb0W" Url="http://dl.delivery.mp.microsoft.com/x/public/fod_desktop_71bd.wim" />
<FileLocation Id="PFMc" Url="http://dl.delivery.mp.microsoft.com/x/public/windows11.0-kb5067039-x64_3c53.cab" />
<FileLocation Id="oldc" Url="http://download.windowsupdate.com/msdownload/windows6.0-kb958690-x86_7e74.cab" />
<FileLocation Id="nope" Url="http://download.windowsupdate.com/msdownload/metadata_7e74.cab" />
</FileLocations>
</OfflineSyncPackage>`

func names(fs []File) string {
	var n []string
	for _, f := range fs {
		n = append(n, f.Name)
	}
	return strings.Join(n, ",")
}

func TestParse(t *testing.T) {
	got, err := Parse(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	// The reported bundle gets its child's files; only the two .msu survive.
	want := "windows11.0-kb5043080-x64_9534.msu,windows11.0-kb5066835-x64_2f19.msu"
	if n := names(got["0c012f79-aa29-4982-aa6d-f1c1058d25ba"]); n != want {
		t.Errorf("bundle files = %s, want %s", n, want)
	}
	if n := names(got["0a9269d1-df26-4ba0-bb32-bfd66bf757d6"]); n != want {
		t.Errorf("child files = %s, want %s", n, want)
	}
	// No .msu: the KB .cab is the package; the metadata cab is dropped.
	if n := names(got["11111111-1111-1111-1111-111111111111"]); n != "windows6.0-kb958690-x86_7e74.cab" {
		t.Errorf("old update files = %s", n)
	}
	if f := got["0c012f79-aa29-4982-aa6d-f1c1058d25ba"][1]; f.Digest != "Lxk7" || !strings.HasPrefix(f.URL, "http://dl.delivery.mp.microsoft.com/") {
		t.Errorf("digest/url not carried: %+v", f)
	}
}

func TestKBOf(t *testing.T) {
	if kb := KBOf("Windows11.0-KB5066835-x64_2f19.msu"); kb != "5066835" {
		t.Errorf("KBOf = %q", kb)
	}
	if kb := KBOf("fod_desktop.wim"); kb != "" {
		t.Errorf("KBOf = %q", kb)
	}
}

func TestParseEmpty(t *testing.T) {
	if _, err := Parse(strings.NewReader(`<OfflineSyncPackage><Updates/></OfflineSyncPackage>`)); err == nil {
		t.Error("want error for a package with no updates")
	}
}
