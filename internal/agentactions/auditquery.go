package agentactions

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxAuditQueryDevices caps one audit_query request: each answer can be up to
// 2 MiB of events, kept in agent_commands.result.
const MaxAuditQueryDevices = 50

// AuditQuery is the filter for audit_query. The agent reads only its own audit
// directory (there is no path field), applies the filter and returns matching
// events newest first.
//
//	mode             tail (default) | search (needs pattern) | since (needs since)
//	limit            1..1000 events, default 100
//	pattern          case-insensitive text match across the event fields
//	since, until     RFC 3339 times, inclusive
//	event_types      any of, e.g. ["command_received", "policy_tampered"]
//	decisions        any of, e.g. ["rejected", "denied"]
//	include_rotated  also read the rotated (older) audit files
type AuditQuery struct {
	Mode           string   `json:"mode,omitempty"`
	Limit          int      `json:"limit,omitempty"`
	Pattern        string   `json:"pattern,omitempty"`
	Since          string   `json:"since,omitempty"`
	Until          string   `json:"until,omitempty"`
	EventTypes     []string `json:"event_types,omitempty"`
	Decisions      []string `json:"decisions,omitempty"`
	IncludeRotated bool     `json:"include_rotated,omitempty"`

	sinceMS, untilMS int64
}

// auditQueryWire is the agent's audit_query/v1 payload (cmd/agent/auditquery.go:
// version + include_rotated + the embedded auditlog.Query fields).
type auditQueryWire struct {
	Version        int      `json:"version"`
	IncludeRotated bool     `json:"include_rotated,omitempty"`
	Mode           string   `json:"mode,omitempty"`
	Limit          int      `json:"limit,omitempty"`
	Pattern        string   `json:"pattern,omitempty"`
	SinceMS        int64    `json:"since_ms,omitempty"`
	UntilMS        int64    `json:"until_ms,omitempty"`
	EventTypes     []string `json:"event_types,omitempty"`
	Decisions      []string `json:"decisions,omitempty"`
}

// validate applies the agent's own rules (a query it would refuse is refused
// here) plus size limits, and normalizes the query.
func (q *AuditQuery) validate() error {
	q.Mode = strings.ToLower(strings.TrimSpace(q.Mode))
	q.Pattern = strings.TrimSpace(q.Pattern)
	if q.Limit < 0 || q.Limit > 1000 {
		return errors.New("query.limit must be 1..1000 (0 = 100)")
	}
	if len(q.Pattern) > 256 {
		return errors.New("query.pattern is longer than 256 characters")
	}
	var err error
	if q.sinceMS, err = parseTime("query.since", q.Since); err != nil {
		return err
	}
	if q.untilMS, err = parseTime("query.until", q.Until); err != nil {
		return err
	}
	if q.sinceMS > 0 && q.untilMS > 0 && q.sinceMS > q.untilMS {
		return errors.New("query.since is after query.until")
	}
	switch q.Mode {
	case "", "tail":
	case "search":
		if q.Pattern == "" {
			return errors.New("query.mode search needs a pattern")
		}
	case "since":
		if q.sinceMS == 0 {
			return errors.New("query.mode since needs since")
		}
	default:
		return fmt.Errorf("query.mode %q: want tail, search or since", q.Mode)
	}
	if q.EventTypes, err = cleanList("query.event_types", q.EventTypes); err != nil {
		return err
	}
	if q.Decisions, err = cleanList("query.decisions", q.Decisions); err != nil {
		return err
	}
	return nil
}

func (q *AuditQuery) wire() auditQueryWire {
	return auditQueryWire{Version: 1, IncludeRotated: q.IncludeRotated, Mode: q.Mode, Limit: q.Limit, Pattern: q.Pattern,
		SinceMS: q.sinceMS, UntilMS: q.untilMS, EventTypes: q.EventTypes, Decisions: q.Decisions}
}

func parseTime(field, s string) (int64, error) {
	if s = strings.TrimSpace(s); s == "" {
		return 0, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("%s must be an RFC 3339 time like 2026-11-14T09:00:00Z", field)
	}
	if t.UnixMilli() <= 0 {
		return 0, fmt.Errorf("%s is before 1970", field)
	}
	return t.UnixMilli(), nil
}

func cleanList(field string, in []string) ([]string, error) {
	if len(in) > 50 {
		return nil, fmt.Errorf("%s: at most 50 values", field)
	}
	var out []string
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if len(v) > 64 {
			return nil, fmt.Errorf("%s: values are at most 64 characters", field)
		}
		out = append(out, v)
	}
	return out, nil
}

// auditEvents pulls the events array out of a stored audit_query result
// (ActionStatus.detail is the agent's JSON array, kept as a string). Anything
// that is not a JSON array is left out.
func auditEvents(result []byte) json.RawMessage {
	var r struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(result, &r) != nil || r.Detail == "" {
		return nil
	}
	var arr []json.RawMessage
	if json.Unmarshal([]byte(r.Detail), &arr) != nil {
		return nil
	}
	return json.RawMessage(r.Detail)
}
