package agentactions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// notify_user (agent 449e47c, docs/server-integration-user-notifications.md in
// the agent repo): the agent shows a tray balloon (info), a window the user
// closes (message) or a prompt with buttons (action) to every logged-on user
// session, through its tray UI. For an action the user's choice comes back as
// ActionStatus (RUNNING while shown or snoozed, SUCCESS "user chose: <label>",
// FAILED when no user session has the UI) and as a user_action_response audit
// event.
//
// The server does NOT enforce deadline_unix: the agent only displays it and
// nothing here sends the follow-up action when it passes (an open decision,
// see docs/agent-operations-api.md).

const (
	maxNotifyTitle   = 128
	maxNotifyText    = 2048
	maxNotifyDetail  = 512
	maxNotifyConfirm = 512
	maxNotifyButton  = 40
	maxNotifyButtons = 4
	maxSnoozeOpts    = 10
	minSnoozeSeconds = 60
	maxSnoozeSeconds = 86400
	maxDeadlineAhead = 30 * 24 * time.Hour
)

// NotifySpec is the notify_user payload: the API body's "notify" object, and
// (validated) exactly what is signed and sent to the agent.
type NotifySpec struct {
	Kind         string   `json:"kind"` // info (default) | message | action
	Title        string   `json:"title"`
	Text         string   `json:"text"`
	Detail       string   `json:"detail,omitempty"`        // action
	Buttons      []string `json:"buttons,omitempty"`       // action; first = accept
	DeadlineUnix int64    `json:"deadline_unix,omitempty"` // action; display only
	AllowSnooze  bool     `json:"allow_snooze,omitempty"`  // action
	SnoozeOpts   []int64  `json:"snooze_opts,omitempty"`   // action, seconds
	ConfirmText  string   `json:"confirm_text,omitempty"`  // action
	OnAccept     string   `json:"on_accept,omitempty"`     // action: "" | "reboot"
}

// Reboots says whether accepting the prompt reboots the device.
func (n *NotifySpec) Reboots() bool { return n != nil && n.OnAccept == "reboot" }

// validate normalizes n and rejects what the agent can't show sensibly.
func (n *NotifySpec) validate(now time.Time) error {
	n.Kind = strings.ToLower(strings.TrimSpace(n.Kind))
	if n.Kind == "" {
		n.Kind = "info"
	}
	if n.Kind != "info" && n.Kind != "message" && n.Kind != "action" {
		return errors.New("notify.kind must be info, message or action")
	}
	var err error
	if n.Title, err = notifyText("notify.title", n.Title, maxNotifyTitle, false); err != nil {
		return err
	}
	if n.Title == "" {
		return errors.New("notify.title is required")
	}
	if n.Text, err = notifyText("notify.text", n.Text, maxNotifyText, true); err != nil {
		return err
	}
	if n.Text == "" {
		return errors.New("notify.text is required")
	}

	if n.Kind != "action" {
		if n.Detail != "" || len(n.Buttons) > 0 || n.DeadlineUnix != 0 || n.AllowSnooze ||
			len(n.SnoozeOpts) > 0 || n.ConfirmText != "" || n.OnAccept != "" {
			return errors.New("detail, buttons, deadline_unix, allow_snooze, snooze_opts, confirm_text and on_accept are only for kind action")
		}
		return nil
	}

	if n.Detail, err = notifyText("notify.detail", n.Detail, maxNotifyDetail, false); err != nil {
		return err
	}
	if n.ConfirmText, err = notifyText("notify.confirm_text", n.ConfirmText, maxNotifyConfirm, true); err != nil {
		return err
	}
	if len(n.Buttons) == 0 || len(n.Buttons) > maxNotifyButtons {
		return fmt.Errorf("notify.buttons: 1..%d labels, the first is the accept button", maxNotifyButtons)
	}
	seen := map[string]bool{}
	for i, b := range n.Buttons {
		if b, err = notifyText("notify.buttons", b, maxNotifyButton, false); err != nil {
			return err
		}
		// The agent reports these back as the choice; they must not collide
		// with its own answers or each other.
		switch strings.ToLower(b) {
		case "", "snoozed", "dismissed", "cancelled":
			return fmt.Errorf("notify.buttons: %q is not a usable label", b)
		}
		if seen[strings.ToLower(b)] {
			return fmt.Errorf("notify.buttons: %q appears twice", b)
		}
		seen[strings.ToLower(b)] = true
		n.Buttons[i] = b
	}
	if n.DeadlineUnix != 0 {
		d := time.Unix(n.DeadlineUnix, 0)
		if !d.After(now) || d.After(now.Add(maxDeadlineAhead)) {
			return errors.New("notify.deadline_unix must be in the future and at most 30 days ahead")
		}
	}
	if len(n.SnoozeOpts) > 0 && !n.AllowSnooze {
		return errors.New("notify.snooze_opts needs allow_snooze")
	}
	if len(n.SnoozeOpts) > maxSnoozeOpts {
		return fmt.Errorf("notify.snooze_opts: at most %d durations", maxSnoozeOpts)
	}
	for _, s := range n.SnoozeOpts {
		if s < minSnoozeSeconds || s > maxSnoozeSeconds {
			return fmt.Errorf("notify.snooze_opts: each %d..%d seconds", minSnoozeSeconds, maxSnoozeSeconds)
		}
	}
	n.OnAccept = strings.ToLower(strings.TrimSpace(n.OnAccept))
	if n.OnAccept != "" && n.OnAccept != "reboot" {
		return errors.New(`notify.on_accept must be empty or "reboot"`)
	}
	return nil
}

// notifyText trims s and checks its length (in characters) and that it has no
// control characters (newlines and tabs allowed when multiline).
func notifyText(field, s string, max int, multiline bool) (string, error) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%s is not valid UTF-8", field)
	}
	if utf8.RuneCountInString(s) > max {
		return "", fmt.Errorf("%s is longer than %d characters", field, max)
	}
	for _, c := range s {
		if unicode.IsControl(c) && !(multiline && (c == '\n' || c == '\t')) {
			return "", fmt.Errorf("%s may not contain control characters", field)
		}
	}
	return s, nil
}

// userResponse is one user_action_response the agent reported for a command.
type userResponse struct {
	TS       time.Time `json:"ts"`
	Decision string    `json:"decision"` // button label | snoozed | dismissed | cancelled
	Reason   string    `json:"reason,omitempty"`
}

// userResponses lists the user_action_response events for a notify_user
// command, oldest first (snoozes, then the final choice).
func (h *Handler) userResponses(ctx context.Context, commandID string) ([]userResponse, error) {
	rows, err := h.pool.Query(ctx, `
		SELECT ts, coalesce(decision, ''), coalesce(reason, '')
		FROM agent_audit_events
		WHERE command_id = $1 AND event_type = 'user_action_response'
		ORDER BY ts LIMIT 200`, commandID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []userResponse
	for rows.Next() {
		var r userResponse
		if err := rows.Scan(&r.TS, &r.Decision, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
