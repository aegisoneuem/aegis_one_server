package agentactions

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNotifyValidate(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	action := func(mod func(*NotifySpec)) NotifySpec {
		n := NotifySpec{Kind: "action", Title: "Restart Required", Text: "Please restart.",
			Buttons: []string{"Restart now", "Later"}}
		if mod != nil {
			mod(&n)
		}
		return n
	}
	ok := []NotifySpec{
		{Title: "Hello", Text: "Patching tonight"},
		{Kind: "MESSAGE", Title: "Maintenance", Text: "line1\nline2\ttabbed"},
		action(nil),
		action(func(n *NotifySpec) {
			n.Detail = "This reboot applies: KB5034441"
			n.DeadlineUnix = now.Add(24 * time.Hour).Unix()
			n.AllowSnooze = true
			n.SnoozeOpts = []int64{60, 3600, 86400}
			n.ConfirmText = "Save your work first."
			n.OnAccept = "Reboot"
		}),
		action(func(n *NotifySpec) { n.AllowSnooze = true }),
	}
	for i, n := range ok {
		if err := n.validate(now); err != nil {
			t.Errorf("ok[%d] %+v: %v", i, n, err)
		}
	}
	bad := map[string]NotifySpec{
		"unknown kind":          {Kind: "popup", Title: "a", Text: "b"},
		"no title":              {Text: "b"},
		"no text":               {Title: "a"},
		"title newline":         {Title: "a\nb", Text: "b"},
		"text control char":     {Title: "a", Text: "b\x07"},
		"long title":            {Title: strings.Repeat("x", maxNotifyTitle+1), Text: "b"},
		"long text":             {Title: "a", Text: strings.Repeat("x", maxNotifyText+1)},
		"buttons on info":       {Title: "a", Text: "b", Buttons: []string{"OK"}},
		"on_accept on message":  {Kind: "message", Title: "a", Text: "b", OnAccept: "reboot"},
		"action without button": action(func(n *NotifySpec) { n.Buttons = nil }),
		"too many buttons":      action(func(n *NotifySpec) { n.Buttons = []string{"a", "b", "c", "d", "e"} }),
		"duplicate button":      action(func(n *NotifySpec) { n.Buttons = []string{"OK", "ok"} }),
		"reserved label":        action(func(n *NotifySpec) { n.Buttons = []string{"Dismissed"} }),
		"empty label":           action(func(n *NotifySpec) { n.Buttons = []string{"OK", "  "} }),
		"long label":            action(func(n *NotifySpec) { n.Buttons = []string{strings.Repeat("x", maxNotifyButton+1)} }),
		"past deadline":         action(func(n *NotifySpec) { n.DeadlineUnix = now.Add(-time.Minute).Unix() }),
		"far deadline":          action(func(n *NotifySpec) { n.DeadlineUnix = now.Add(31 * 24 * time.Hour).Unix() }),
		"snooze opts no snooze": action(func(n *NotifySpec) { n.SnoozeOpts = []int64{60} }),
		"snooze too short":      action(func(n *NotifySpec) { n.AllowSnooze = true; n.SnoozeOpts = []int64{30} }),
		"snooze too long":       action(func(n *NotifySpec) { n.AllowSnooze = true; n.SnoozeOpts = []int64{86401} }),
		"bad on_accept":         action(func(n *NotifySpec) { n.OnAccept = "shutdown" }),
	}
	for name, n := range bad {
		if err := n.validate(now); err == nil {
			t.Errorf("%s: accepted %+v", name, n)
		}
	}

	n := action(func(n *NotifySpec) {
		n.Title = "  Restart  "
		n.Buttons = []string{" Now ", "Later"}
		n.OnAccept = " REBOOT "
	})
	if err := n.validate(now); err != nil {
		t.Fatal(err)
	}
	if n.Title != "Restart" || n.Buttons[0] != "Now" || n.OnAccept != "reboot" || !n.Reboots() {
		t.Errorf("not normalized: %+v", n)
	}
	info := NotifySpec{Title: "a", Text: "b"}
	if info.validate(now); info.Kind != "info" || info.Reboots() {
		t.Errorf("kind default: %+v", info)
	}
}

func TestNotifyRequestValidate(t *testing.T) {
	if err := validate(&Request{Action: "notify_user"}); err == nil {
		t.Error("notify_user without notify accepted")
	}
	if err := validate(&Request{Action: "reboot", Notify: &NotifySpec{Title: "a", Text: "b"}}); err == nil {
		t.Error("notify on reboot accepted")
	}
	if err := validate(&Request{Action: "notify_user", Message: "x", Notify: &NotifySpec{Title: "a", Text: "b"}}); err == nil {
		t.Error("reboot message on notify_user accepted")
	}
	if err := validate(&Request{Action: "notify_user", Notify: &NotifySpec{Title: "a", Text: "b"}}); err != nil {
		t.Error(err)
	}
	var nilSpec *NotifySpec
	if nilSpec.Reboots() {
		t.Error("nil spec reboots")
	}
}

// The wire payload must use the agent's field names (cmd/agent/notifyuser.go)
// and leave out what isn't set.
func TestNotifyWire(t *testing.T) {
	h := &Handler{}
	req := Request{Action: "notify_user", Notify: &NotifySpec{Kind: "action", Title: "T", Text: "X",
		Buttons: []string{"Yes", "No"}, DeadlineUnix: 1795000000, AllowSnooze: true, SnoozeOpts: []int64{60},
		ConfirmText: "Sure?", OnAccept: "reboot", Detail: "D"}}
	wire, audit, err := h.payload(t.Context(), req, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"kind", "title", "text", "detail", "buttons", "deadline_unix", "allow_snooze",
		"snooze_opts", "confirm_text", "on_accept"} {
		if _, ok := got[k]; !ok {
			t.Errorf("wire lacks %s: %s", k, wire)
		}
	}
	if audit["on_accept"] != "reboot" || audit["title"] != "T" {
		t.Errorf("audit: %v", audit)
	}

	wire, _, _ = h.payload(t.Context(), Request{Action: "notify_user", Notify: &NotifySpec{Kind: "info", Title: "T", Text: "X"}}, "dev-1")
	if string(wire) != `{"kind":"info","title":"T","text":"X"}` {
		t.Errorf("info wire: %s", wire)
	}
}

func TestNotifyReadPerm(t *testing.T) {
	if readPerm("notify_user") != "user.notify" {
		t.Errorf("readPerm(notify_user) = %s", readPerm("notify_user"))
	}
}
