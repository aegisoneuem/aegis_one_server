package enroll

import "testing"

type fakeLive map[string]bool

func (f fakeLive) Connected(id string) bool { return f[id] }

func TestClassify(t *testing.T) {
	strong := func(by string) *match { return &match{dev: device{deviceID: "dev-1"}, by: by, strong: true} }
	weak := func(by string) *match { return &match{dev: device{deviceID: "dev-1"}, by: by} }

	cases := []struct {
		name       string
		m          *match
		live       Live
		act        bool
		reviewedBy string
	}{
		{"no match", nil, fakeLive{}, false, ""},
		{"tpm, record offline", strong("tpm_ek"), fakeLive{}, true, ""},
		{"tpm, no live check", strong("tpm_ek"), nil, true, ""},
		{"device_id, record offline", strong("device_id"), fakeLive{}, true, ""},
		{"tpm, record connected", strong("tpm_ek"), fakeLive{"dev-1": true}, false, "tpm_ek_conflict"},
		{"device_id, record connected", strong("device_id"), fakeLive{"dev-1": true}, false, "device_id_conflict"},
		{"smbios uuid", weak("system_uuid"), fakeLive{}, false, "system_uuid"},
		{"machine guid, record connected", weak("machine_guid"), fakeLive{"dev-1": true}, false, "machine_guid"},
	}
	for _, c := range cases {
		act, review := classify(c.m, c.live)
		if (act != nil) != c.act {
			t.Errorf("%s: act = %v, want %v", c.name, act != nil, c.act)
		}
		got := ""
		if review != nil {
			got = review.by
		}
		if got != c.reviewedBy {
			t.Errorf("%s: review = %q, want %q", c.name, got, c.reviewedBy)
		}
		if act != nil && review != nil {
			t.Errorf("%s: both act and review set", c.name)
		}
	}
	// classify must not rename the caller's match.
	m := strong("tpm_ek")
	classify(m, fakeLive{"dev-1": true})
	if m.by != "tpm_ek" {
		t.Errorf("caller's match changed to %q", m.by)
	}
}

func TestRenamed(t *testing.T) {
	d := Renamed("PC-OLD", "PC-NEW")
	if d["message"] != "Device renamed from PC-OLD to PC-NEW" || d["from"] != "PC-OLD" || d["to"] != "PC-NEW" {
		t.Errorf("got %v", d)
	}
}
