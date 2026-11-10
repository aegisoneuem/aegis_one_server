package patchdeploy

import (
	"testing"

	"aegis-one/internal/wucatalog"
)

func TestInstallPlan(t *testing.T) {
	f := func(name, digest string) wucatalog.File { return wucatalog.File{Name: name, Digest: digest} }
	// A 24H2-style cumulative: its own .msu plus two checkpoints, listed by name.
	plan, err := installPlan([]wucatalog.File{
		f("windows11.0-kb5066835-x64_aaa.msu", "d-main"),
		f("windows11.0-kb5043080-x64_bbb.msu", "d-cp1"),
		f("windows11.0-kb5043080-x64_bbb.msu", "d-cp1"), // duplicate row
		f("windows11.0-kb5055523-x64_ccc.msu", "d-cp2"),
	}, "KB5066835")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range plan {
		got = append(got, p.KB+"/"+p.Digest)
	}
	want := []string{"KB5043080/d-cp1", "KB5055523/d-cp2", "KB5066835/d-main"}
	if len(got) != len(want) {
		t.Fatalf("plan %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plan %v, want %v", got, want)
		}
	}

	// One file: just that file.
	if plan, err := installPlan([]wucatalog.File{f("windows10.0-kb5066791-x64_aa.cab", "d")}, "KB5066791"); err != nil || len(plan) != 1 {
		t.Errorf("single file: %v %v", plan, err)
	}
	// Numeric, not string, KB order: KB999999 is older than KB5000000.
	plan, _ = installPlan([]wucatalog.File{
		f("windows11.0-kb6000000-x64_a.msu", "m"), f("windows11.0-kb5000000-x64_b.msu", "b"), f("windows11.0-kb999999-x64_c.msu", "c"),
	}, "KB6000000")
	if plan[0].KB != "KB999999" || plan[1].KB != "KB5000000" {
		t.Errorf("order by KB number: %+v", plan)
	}

	for name, files := range map[string][]wucatalog.File{
		"no file for the kb":   {f("windows11.0-kb5043080-x64_bbb.msu", "x")},
		"two files for the kb": {f("windows11.0-kb5066835-x64_a.msu", "1"), f("windows11.0-kb5066835-x64_b.msu", "2")},
		"too many files": {f("windows11.0-kb7-x64_a.msu", "m"), f("windows11.0-kb1-x64_a.msu", "1"), f("windows11.0-kb2-x64_a.msu", "2"),
			f("windows11.0-kb3-x64_a.msu", "3"), f("windows11.0-kb4-x64_a.msu", "4"), f("windows11.0-kb5-x64_a.msu", "5"), f("windows11.0-kb6-x64_a.msu", "6")},
	} {
		kb := "KB5066835"
		if name == "too many files" {
			kb = "KB7"
		}
		if _, err := installPlan(files, kb); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRowFiles(t *testing.T) {
	legacy := row{kb: "KB1"}
	if legacy.fileKB() != "KB1" || !legacy.lastFile() || legacy.fileLabel() != "" || legacy.fileResult() != nil {
		t.Errorf("one-file row from before 0022 must keep the old flow")
	}
	files := []PlanFile{{KB: "KB5043080", Name: "cp.msu"}, {KB: "KB5066835", Name: "main.msu"}}
	x := row{kb: "KB5066835", files: files}
	if x.fileKB() != "KB5043080" || x.lastFile() || x.fileLabel() != "file 1/2 (KB5043080): " {
		t.Errorf("first file: kb=%s last=%v label=%q", x.fileKB(), x.lastFile(), x.fileLabel())
	}
	x.fileIndex = 1
	if x.fileKB() != "KB5066835" || !x.lastFile() {
		t.Errorf("second file: kb=%s last=%v", x.fileKB(), x.lastFile())
	}
}

func TestArchMatches(t *testing.T) {
	cases := []struct {
		name, arch string
		want       bool
	}{
		{"windows11.0-kb5066835-x64_1a2b3c.msu", "x64", true},
		{"windows11.0-kb5066835-arm64_1a2b3c.msu", "arm64", true},
		{"windows11.0-kb5066835-arm64_1a2b3c.msu", "x64", false},
		{"Windows10.0-KB5066791-X86_aa.cab", "x86", true},
		{"windows10.0-kb5066791-x86_aa.cab", "x64", false},
		{"windows11.0-kb5066835-x64.msu", "x64", true},
		{"anything.msu", "", false},
	}
	for _, c := range cases {
		if got := ArchMatches(c.name, c.arch); got != c.want {
			t.Errorf("ArchMatches(%q, %q) = %v, want %v", c.name, c.arch, got, c.want)
		}
	}
}
