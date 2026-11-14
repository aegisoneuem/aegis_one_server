package agentactions

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditQueryValidate(t *testing.T) {
	ok := []Request{
		{Action: "audit_query"}, // empty query = last 100 events
		{Action: "audit_query", Query: &AuditQuery{Mode: "search", Pattern: "run_command", Limit: 1000}},
		{Action: "audit_query", Query: &AuditQuery{Mode: "since", Since: "2026-11-14T09:00:00+05:30", Until: "2026-11-14T10:00:00Z"}},
		{Action: "audit_query", Query: &AuditQuery{EventTypes: []string{"Policy_Tampered"}, Decisions: []string{"rejected"}, IncludeRotated: true}},
	}
	for _, r := range ok {
		if err := validate(&r); err != nil {
			t.Errorf("%+v: %v", r.Query, err)
		}
	}
	bad := map[string]Request{
		"search without pattern": {Action: "audit_query", Query: &AuditQuery{Mode: "search"}},
		"since without since":    {Action: "audit_query", Query: &AuditQuery{Mode: "since"}},
		"unknown mode":           {Action: "audit_query", Query: &AuditQuery{Mode: "grep"}},
		"limit over 1000":        {Action: "audit_query", Query: &AuditQuery{Limit: 1001}},
		"negative limit":         {Action: "audit_query", Query: &AuditQuery{Limit: -1}},
		"bad time":               {Action: "audit_query", Query: &AuditQuery{Since: "yesterday"}},
		"since after until":      {Action: "audit_query", Query: &AuditQuery{Since: "2026-11-14T10:00:00Z", Until: "2026-11-14T09:00:00Z"}},
		"long pattern":           {Action: "audit_query", Query: &AuditQuery{Pattern: strings.Repeat("x", 257)}},
		"query on reboot":        {Action: "reboot", Query: &AuditQuery{}},
	}
	for name, r := range bad {
		if err := validate(&r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The payload must use the agent's audit_query/v1 field names.
func TestAuditQueryWire(t *testing.T) {
	r := Request{Action: "audit_query", Query: &AuditQuery{Mode: "Search", Pattern: " shell ", Limit: 5,
		Since: "2026-11-14T09:00:00Z", EventTypes: []string{" Command_Received ", ""}, IncludeRotated: true}}
	if err := validate(&r); err != nil {
		t.Fatal(err)
	}
	b, audit, err := (&Handler{}).payload(t.Context(), r, "dev")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	json.Unmarshal(b, &got)
	want := map[string]any{"version": float64(1), "mode": "search", "pattern": "shell", "limit": float64(5),
		"since_ms": float64(1794646800000), "include_rotated": true}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (payload %s)", k, got[k], v, b)
		}
	}
	if ev, _ := got["event_types"].([]any); len(ev) != 1 || ev[0] != "command_received" {
		t.Errorf("event_types = %v", got["event_types"])
	}
	if _, ok := got["until_ms"]; ok {
		t.Error("unset until_ms sent")
	}
	if audit["pattern"] != "shell" {
		t.Errorf("audit form: %v", audit)
	}
}

func TestAuditEvents(t *testing.T) {
	good := []byte(`{"phase":"ACTION_PHASE_SUCCESS","detail":"[{\"event_type\":\"command_received\"}]"}`)
	if got := string(auditEvents(good)); got != `[{"event_type":"command_received"}]` {
		t.Errorf("events = %s", got)
	}
	for _, r := range []string{`{"detail":""}`, `{"detail":"not json"}`, `{"detail":"{\"a\":1}"}`, `not json`} {
		if auditEvents([]byte(r)) != nil {
			t.Errorf("%s: events returned", r)
		}
	}
}
