package agentactions

import "testing"

func TestValidate(t *testing.T) {
	ok := []Request{
		{Action: "reboot", DelaySeconds: 300, Message: "Patching tonight"},
		{Action: "reboot"},
		{Action: "cancel_reboot"},
		{Action: "uninstall_patch", KB: "kb5034441"},
		{Action: "uninstall_patch", KB: "5034441"},
		{Action: "scan_now"},
		{Action: "report_device_state"},
	}
	for _, r := range ok {
		if err := validate(&r); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	bad := []Request{
		{Action: "reboot", DelaySeconds: -1},
		{Action: "reboot", DelaySeconds: 86401},
		{Action: "reboot", Message: "line1\nline2"},
		{Action: "reboot", Message: `say "hi"`},
		{Action: "uninstall_patch"},
		{Action: "uninstall_patch", KB: "KB12"},
		{Action: "scan_now", KB: "KB5034441"},
		{Action: "cancel_reboot", DelaySeconds: 5},
	}
	for _, r := range bad {
		if err := validate(&r); err == nil {
			t.Errorf("%+v: accepted", r)
		}
	}
	r := Request{Action: "uninstall_patch", KB: " kb5034441 "}
	if validate(&r); r.KB != "KB5034441" {
		t.Errorf("kb not normalized: %q", r.KB)
	}
}
