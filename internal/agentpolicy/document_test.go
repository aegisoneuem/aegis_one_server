package agentpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRequest(t *testing.T) {
	d, err := ParseRequest([]byte(`{"modules":{"deny":[" Run_Command ","open_shell","run_command"]},
		"patch":{"reboot_policy":"Never"},"maintenance":{"days":["Sat","sun"],"start_hour":22,"end_hour":4},
		"transfer":{"fetch_max_bytes_per_second":1048576},"logging":{"level":"WARN"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.Modules.Deny, ",") != "run_command,open_shell" || d.Patch.RebootPolicy != "never" ||
		strings.Join(d.Maintenance.Days, ",") != "sat,sun" || d.Logging.Level != "warn" {
		t.Errorf("normalized: %+v", d)
	}

	bad := map[string]string{
		"server field":      `{"issued_at": 5}`,
		"policy id":         `{"policy_id": "x"}`,
		"unknown field":     `{"modules":{"deny":["reboot"]},"reboot_policy":"never"}`,
		"misspelt section":  `{"maintainance":{"days":["mon"]}}`,
		"unknown command":   `{"modules":{"deny":["run_comand"]}}`,
		"deny set_policy":   `{"modules":{"deny":["set_policy"]}}`,
		"bad day":           `{"maintenance":{"days":["monday"]}}`,
		"bad hour":          `{"maintenance":{"start_hour":24}}`,
		"bad reboot":        `{"patch":{"reboot_policy":"sometimes"}}`,
		"bad level":         `{"logging":{"level":"trace"}}`,
		"negative cap":      `{"transfer":{"upload_max_bytes_per_second":-1}}`,
		"negative interval": `{"checkin":{"heartbeat_interval_seconds":-5}}`,
		"not an object":     `[1]`,
	}
	for name, raw := range bad {
		if _, err := ParseRequest([]byte(raw)); err == nil {
			t.Errorf("%s: accepted %s", name, raw)
		}
	}
}

// The wire document must decode with the agent's field names.
func TestWireFieldNames(t *testing.T) {
	d, _ := ParseRequest([]byte(`{"security_floor":{"require_fips":true},"modules":{"allow":["install_patch"]},
		"transfer":{"upload_max_bytes_per_second":10},"audit":{"rate_per_sec":5},"checkin":{"heartbeat_interval_seconds":60}}`))
	d.Version, d.PolicyID, d.IssuedAt = 1, "p", 100
	b, _ := json.Marshal(d)
	for _, want := range []string{`"version":1`, `"policy_id":"p"`, `"issued_at":100`, `"security_floor":{"require_fips":true}`,
		`"modules":{"allow":["install_patch"]}`, `"upload_max_bytes_per_second":10`, `"rate_per_sec":5`, `"checkin":{"heartbeat_interval_seconds":60}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("wire %s lacks %s", b, want)
		}
	}
}

func TestNeedsPush(t *testing.T) {
	i := func(v int64) *int64 { return &v }
	s := func(v string) *string { return &v }
	cases := []struct {
		name string
		st   agentState
		want bool
	}{
		{"never pushed", agentState{agentVersion: "1"}, true},
		{"older version", agentState{agentVersion: "1", issuedAt: i(9), status: s("applied")}, true},
		{"applied", agentState{agentVersion: "1", issuedAt: i(10), status: s("applied")}, false},
		{"pending", agentState{agentVersion: "1", issuedAt: i(10), status: s("pending")}, true},
		{"tampered", agentState{agentVersion: "1", issuedAt: i(10), status: s("tampered")}, true},
		{"failed same build", agentState{agentVersion: "1", issuedAt: i(10), status: s("failed"), stateVersion: s("1")}, false},
		{"failed, agent upgraded", agentState{agentVersion: "2", issuedAt: i(10), status: s("failed"), stateVersion: s("1")}, true},
	}
	for _, c := range cases {
		if got := needsPush(c.st, 10); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
