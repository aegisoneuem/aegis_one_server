// Package agentpolicy publishes the fleet-wide signed agent policy and pushes it
// to agents (migration 0025).
//
// The agent (cmd/agent/policy.go, internal/policy in the agent repo) takes the
// policy as the JSON payload of an Ed25519-signed set_policy command, stores it,
// re-verifies it at startup and refuses any document whose issued_at is not newer
// than the one it has (anti-rollback). Re-sending the version it already has is
// answered NOT_APPLICABLE, except in fail-closed safe mode (stored policy deleted
// or edited), where the same version is accepted again. That makes "push the
// current version on connect, and again after a tamper report" safe.
package agentpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Document is the agent's policy schema, version 1. Field names and JSON tags
// must match the agent's internal/policy.Policy exactly: the agent parses this.
type Document struct {
	Version       int           `json:"version"`
	PolicyID      string        `json:"policy_id"`
	IssuedAt      int64         `json:"issued_at"`
	SecurityFloor SecurityFloor `json:"security_floor"`
	Modules       Modules       `json:"modules"`
	Patch         Patch         `json:"patch"`
	Inventory     Inventory     `json:"inventory"`
	Transfer      Transfer      `json:"transfer"`
	Maintenance   Maintenance   `json:"maintenance"`
	Audit         Audit         `json:"audit"`
	Logging       Logging       `json:"logging"`
	CheckIn       CheckIn       `json:"checkin"`
}

type SecurityFloor struct {
	RequireFIPS           bool   `json:"require_fips,omitempty"`
	RequireSignedCommands bool   `json:"require_signed_commands,omitempty"`
	MinTLS                string `json:"min_tls,omitempty"`
}

type Modules struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

type Patch struct {
	RebootPolicy           string `json:"reboot_policy,omitempty"`
	InstallIfRebootPending *bool  `json:"install_if_reboot_pending,omitempty"`
	DirectVendorDownload   *bool  `json:"direct_vendor_download,omitempty"`
	ScanIntervalSeconds    int64  `json:"scan_interval_seconds,omitempty"`
	MaxAttempts            int    `json:"max_attempts,omitempty"`
}

type Inventory struct {
	FullIntervalSeconds        int64 `json:"full_interval_seconds,omitempty"`
	DeviceStateIntervalSeconds int64 `json:"device_state_interval_seconds,omitempty"`
	ScanOnLogin                *bool `json:"scan_on_login,omitempty"`
	ScanOnIPChange             *bool `json:"scan_on_ip_change,omitempty"`
}

type Transfer struct {
	FetchMaxBPS      int64 `json:"fetch_max_bytes_per_second,omitempty"`
	UploadMaxBPS     int64 `json:"upload_max_bytes_per_second,omitempty"`
	PeerCacheEnabled *bool `json:"peer_cache_enabled,omitempty"`
}

type Maintenance struct {
	Days      []string `json:"days,omitempty"`
	StartHour int      `json:"start_hour,omitempty"`
	EndHour   int      `json:"end_hour,omitempty"`
}

type Audit struct {
	RatePerSec         int   `json:"rate_per_sec,omitempty"`
	Burst              int   `json:"burst,omitempty"`
	DedupWindowSeconds int64 `json:"dedup_window_seconds,omitempty"`
}

type Logging struct {
	Level string `json:"level,omitempty"`
}

type CheckIn struct {
	HeartbeatIntervalSeconds int64 `json:"heartbeat_interval_seconds,omitempty"`
}

// CommandTypes the agent's module allow/deny lists can name (its dispatcher
// table, 2026-11-12). A typo in a deny list would silently deny nothing, and in
// an allow list would block the real command, so unknown names are refused.
var CommandTypes = map[string]bool{
	"install_patch": true, "uninstall_patch": true, "stage_patch": true,
	"software_deploy": true, "software_deploy_v2": true, "software_deploy_bundle": true,
	"software_deploy_workflow": true, "software_deploy_detect": true,
	"scan_now": true, "scan": true, "reboot": true, "cancel_reboot": true, "report_device_state": true,
	"run_command": true, "open_shell": true, "file_operation": true, "collect_file": true,
	"audit_query": true, "set_policy": true, "remote_control": true,
}

var days = map[string]bool{"mon": true, "tue": true, "wed": true, "thu": true, "fri": true, "sat": true, "sun": true}

// ParseRequest decodes the policy part of a publish request. Unknown fields are
// refused (a misspelt setting would otherwise be dropped without a word), and
// version / policy_id / issued_at are set by the server, not the caller.
func ParseRequest(raw []byte) (*Document, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("policy must be a JSON object: %w", err)
	}
	for _, k := range []string{"version", "policy_id", "issued_at"} {
		if _, ok := probe[k]; ok {
			return nil, fmt.Errorf("%s is set by the server; leave it out", k)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	if dec.More() {
		return nil, errors.New("invalid policy: trailing data")
	}
	d.normalize()
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// normalize lower-cases and trims the enumerated values so what is stored and
// signed is canonical (the agent compares them case-insensitively anyway).
func (d *Document) normalize() {
	low := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	lowAll := func(in []string) []string {
		out := make([]string, 0, len(in))
		seen := map[string]bool{}
		for _, s := range in {
			if s = low(s); s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	d.Modules.Allow, d.Modules.Deny = lowAll(d.Modules.Allow), lowAll(d.Modules.Deny)
	d.Maintenance.Days = lowAll(d.Maintenance.Days)
	d.Patch.RebootPolicy = low(d.Patch.RebootPolicy)
	d.Logging.Level = low(d.Logging.Level)
	d.SecurityFloor.MinTLS = strings.TrimSpace(d.SecurityFloor.MinTLS)
}

// validate applies the agent's own Validate rules (a document it would refuse
// must never be published) plus the checks above.
func (d *Document) validate() error {
	for _, list := range [][]string{d.Modules.Allow, d.Modules.Deny} {
		for _, c := range list {
			if !CommandTypes[c] {
				return fmt.Errorf("modules: unknown command type %q", c)
			}
		}
	}
	for _, c := range d.Modules.Deny {
		if c == "set_policy" {
			return errors.New("modules: set_policy cannot be denied (the agent always accepts a newer policy)")
		}
	}
	switch d.Patch.RebootPolicy {
	case "", "never", "if_required", "always":
	default:
		return fmt.Errorf("patch.reboot_policy %q: want never, if_required or always", d.Patch.RebootPolicy)
	}
	switch d.Logging.Level {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level %q: want debug, info, warn or error", d.Logging.Level)
	}
	switch d.SecurityFloor.MinTLS {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("security_floor.min_tls %q: want 1.2 or 1.3", d.SecurityFloor.MinTLS)
	}
	for _, day := range d.Maintenance.Days {
		if !days[day] {
			return fmt.Errorf("maintenance.days: %q is not one of mon, tue, wed, thu, fri, sat, sun", day)
		}
	}
	m := d.Maintenance
	if m.StartHour < 0 || m.StartHour > 23 || m.EndHour < 0 || m.EndHour > 23 {
		return errors.New("maintenance.start_hour / end_hour must be 0-23")
	}
	if d.Transfer.FetchMaxBPS < 0 || d.Transfer.UploadMaxBPS < 0 {
		return errors.New("transfer bandwidth caps must not be negative")
	}
	for _, n := range []int64{d.Patch.ScanIntervalSeconds, d.Inventory.FullIntervalSeconds, d.Inventory.DeviceStateIntervalSeconds,
		d.Audit.DedupWindowSeconds, d.CheckIn.HeartbeatIntervalSeconds, int64(d.Patch.MaxAttempts), int64(d.Audit.RatePerSec), int64(d.Audit.Burst)} {
		if n < 0 {
			return errors.New("intervals, counts and rates must not be negative")
		}
	}
	return nil
}

// Summary is a short line for audit and logs.
func (d *Document) Summary() string {
	return fmt.Sprintf("issued_at=%d require_fips=%t allow=%d deny=%d reboot_policy=%q maintenance=%v/%d-%d",
		d.IssuedAt, d.SecurityFloor.RequireFIPS, len(d.Modules.Allow), len(d.Modules.Deny), d.Patch.RebootPolicy,
		d.Maintenance.Days, d.Maintenance.StartHour, d.Maintenance.EndHour)
}
