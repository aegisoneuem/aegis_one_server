package enroll

import "testing"

type fakeLive map[string]bool

func (f fakeLive) Connected(id string) bool { return f[id] }

func TestClassify(t *testing.T) {
	// A record whose identity nobody can prove any more (retired, or no live cert).
	strong := func(by string) *match {
		return &match{dev: device{deviceID: "dev-1", state: "offline"}, by: by, strong: true}
	}
	// A record whose agent still holds a valid certificate.
	live := func(by, state string) *match {
		return &match{dev: device{deviceID: "dev-1", state: state, liveCert: true}, by: by, strong: true}
	}
	weak := func(by string) *match { return &match{dev: device{deviceID: "dev-1"}, by: by} }

	cases := []struct {
		name       string
		m          *match
		live       Live
		reenroll   string
		act        bool
		reviewedBy string
	}{
		{"no match", nil, fakeLive{}, "", false, ""},
		{"tpm, record offline, certs expired", strong("tpm_ek"), fakeLive{}, "", true, ""},
		{"tpm, no live check", strong("tpm_ek"), nil, "", true, ""},
		{"device_id, record offline, certs expired", strong("device_id"), fakeLive{}, "", true, ""},
		{"tpm, record connected", strong("tpm_ek"), fakeLive{"dev-1": true}, "", false, "tpm_ek_conflict"},
		{"device_id, record connected", strong("device_id"), fakeLive{"dev-1": true}, "", false, "device_id_conflict"},
		{"smbios uuid", weak("system_uuid"), fakeLive{}, "", false, "system_uuid"},
		{"machine guid, record connected", weak("machine_guid"), fakeLive{"dev-1": true}, "", false, "machine_guid"},
		// The identity is still provable over mTLS: a bare token can't take it.
		{"device_id, record offline but live cert", live("device_id", "offline"), fakeLive{}, "", false, "device_id_conflict"},
		{"tpm, record stale but live cert", live("tpm_ek", "stale"), fakeLive{}, "", false, "tpm_ek_conflict"},
		{"device_id, live cert, no live check", live("device_id", "offline"), nil, "", false, "device_id_conflict"},
		// Retired by an admin: reactivation is the documented way back.
		{"tpm, retired, cert rows left over", live("tpm_ek", "retired"), fakeLive{}, "", true, ""},
		// An admin bound the token to this device.
		{"device_id, live cert, token bound to it", live("device_id", "offline"), fakeLive{}, "dev-1", true, ""},
		{"device_id, live cert, token bound elsewhere", live("device_id", "offline"), fakeLive{}, "dev-2", false, "device_id_conflict"},
		{"device_id, bound token but connected", live("device_id", "online"), fakeLive{"dev-1": true}, "dev-1", false, "device_id_conflict"},
		{"weak match, bound token", weak("system_uuid"), fakeLive{}, "dev-1", false, "system_uuid"},
	}
	for _, c := range cases {
		act, review := classify(c.m, c.live, c.reenroll)
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
	classify(m, fakeLive{"dev-1": true}, "")
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
