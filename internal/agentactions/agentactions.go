// Package agentactions sends the agent's simple device commands to one or
// more online devices:
//
//	POST /internal/actions  {"action": "...", "device_ids": [...], ...params}
//	GET  /internal/actions?command_id=<id>   status and result of any command (needs
//	                                         the permission that sending it needs)
//
// Actions and the permission each needs:
//
//	reboot               device.reboot   {delay_seconds 0..86400, message <=512}
//	cancel_reboot        device.reboot   cancels ANY pending OS shutdown (shutdown /a)
//	uninstall_patch      patch.deploy    {kb}; the device's build is sent so the
//	                                     agent can find a cumulative update's package
//	scan_now             devices.view    runs the optional cab scan if the endpoint has a cab
//	report_device_state  devices.view    forces a DeviceStateReport (and so a patch re-diff)
//
// Only online devices get the command (see commands.Sender): these carry no
// expiry, so nothing is queued for later.
package agentactions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/apiauth"
	"aegis-one/internal/commands"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// MaxDevices caps one request.
const MaxDevices = 1000

type Handler struct {
	pool   *pgxpool.Pool
	sender *commands.Sender
	log    *slog.Logger
}

func New(pool *pgxpool.Pool, sender *commands.Sender, log *slog.Logger) *Handler {
	return &Handler{pool: pool, sender: sender, log: log}
}

// Request is the POST body.
type Request struct {
	Action       string   `json:"action"`
	DeviceIDs    []string `json:"device_ids"`
	DelaySeconds int32    `json:"delay_seconds,omitempty"` // reboot
	Message      string   `json:"message,omitempty"`       // reboot
	KB           string   `json:"kb,omitempty"`            // uninstall_patch
}

// permFor is the permission an action needs.
var permFor = map[string]string{
	"reboot":              apiauth.PermDeviceReboot,
	"cancel_reboot":       apiauth.PermDeviceReboot,
	"uninstall_patch":     apiauth.PermPatchDeploy,
	"scan_now":            apiauth.PermDevicesView,
	"report_device_state": apiauth.PermDevicesView,
}

var kbRe = regexp.MustCompile(`^KB[0-9]{4,8}$`)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.create(w, r)
	case http.MethodGet:
		h.status(w, r)
	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	caller, ok := apiauth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var req Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	perm, known := permFor[req.Action]
	if !known {
		http.Error(w, "action must be one of reboot, cancel_reboot, uninstall_patch, scan_now, report_device_state", http.StatusUnprocessableEntity)
		return
	}
	if !caller.Can(perm) {
		apiauth.Deny(w, h.log, caller, perm, r)
		return
	}
	devices := dedupe(req.DeviceIDs)
	if len(devices) == 0 || len(devices) > MaxDevices {
		http.Error(w, fmt.Sprintf("device_ids: 1..%d devices", MaxDevices), http.StatusUnprocessableEntity)
		return
	}
	if err := validate(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	results := make([]commands.Sent, 0, len(devices))
	counts := map[string]int{}
	for _, dev := range devices {
		wire, audit, err := h.payload(r.Context(), req, dev)
		if err != nil {
			h.log.Error("agent action: build payload", "action", req.Action, "device_id", dev, "error", err.Error())
			http.Error(w, "could not build the command", http.StatusInternalServerError)
			return
		}
		sent, err := h.sender.Send(r.Context(), commands.SendRequest{
			DeviceID: dev, Type: req.Action, Wire: wire, Audit: audit,
			ClientID: caller.ClientID, ClientName: caller.ClientName, Actor: "api_client:" + caller.ClientName,
		})
		if err != nil {
			h.log.Error("agent action: send", "action", req.Action, "device_id", dev, "error", err.Error())
			sent = commands.Sent{DeviceID: dev, Status: "failed", Error: "server error"}
		}
		counts[sent.Status]++
		results = append(results, sent)
	}
	h.log.Info("agent action sent", "action", req.Action, "devices", len(devices), "dispatched", counts["dispatched"],
		"offline", counts["offline"], "client", caller.ClientName)
	writeJSON(w, http.StatusAccepted, map[string]any{"action": req.Action, "counts": counts, "results": results})
}

func validate(req *Request) error {
	switch req.Action {
	case "reboot":
		if req.DelaySeconds < 0 || req.DelaySeconds > 86400 {
			return errors.New("delay_seconds must be 0..86400")
		}
		req.Message = strings.TrimSpace(req.Message)
		if len(req.Message) > 512 {
			return errors.New("message is longer than 512 characters")
		}
		for _, c := range req.Message {
			if unicode.IsControl(c) || c == '"' {
				return errors.New("message may not contain control characters or double quotes")
			}
		}
	case "uninstall_patch":
		req.KB = strings.ToUpper(strings.TrimSpace(req.KB))
		if !strings.HasPrefix(req.KB, "KB") {
			req.KB = "KB" + req.KB
		}
		if !kbRe.MatchString(req.KB) {
			return errors.New("kb must look like KB5034441")
		}
	}
	if req.Action != "reboot" && (req.DelaySeconds != 0 || req.Message != "") {
		return errors.New("delay_seconds and message are only for reboot")
	}
	if req.Action != "uninstall_patch" && req.KB != "" {
		return errors.New("kb is only for uninstall_patch")
	}
	return nil
}

// payload builds the wire payload and its audit form for one device.
func (h *Handler) payload(ctx context.Context, req Request, deviceID string) ([]byte, map[string]any, error) {
	switch req.Action {
	case "reboot":
		b, err := proto.Marshal(&aegisonev1.RebootSpec{DelaySeconds: req.DelaySeconds, Message: req.Message})
		return b, map[string]any{"delay_seconds": req.DelaySeconds, "message": req.Message}, err
	case "uninstall_patch":
		// The agent finds a cumulative update's CBS package by build, not KB.
		var build *string
		var ubr *int
		err := h.pool.QueryRow(ctx, `SELECT os_build, os_ubr FROM devices WHERE agent_reported_id = $1`, deviceID).Scan(&build, &ubr)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, err
		}
		full := ""
		if build != nil && ubr != nil {
			full = fmt.Sprintf("%s.%d", *build, *ubr)
		}
		b, err := proto.Marshal(&aegisonev1.InstallPatchSpec{Kb: req.KB, OsBuild: full})
		return b, map[string]any{"kb": req.KB, "os_build": full}, err
	default: // cancel_reboot, scan_now, report_device_state: no payload
		return []byte{}, map[string]any{}, nil
	}
}

type statusView struct {
	CommandID   string          `json:"command_id"`
	DeviceID    string          `json:"device_id"`
	Type        string          `json:"type"`
	Status      string          `json:"status"`
	Payload     json.RawMessage `json:"payload"`
	Result      json.RawMessage `json:"result,omitempty"`
	IssuedAt    time.Time       `json:"issued_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("command_id")
	if !commands.IsCommandID(id) {
		http.Error(w, "command_id is required", http.StatusBadRequest)
		return
	}
	var v statusView
	var result []byte
	err := h.pool.QueryRow(r.Context(), `
		SELECT c.id::text, d.agent_reported_id, c.command_type, c.status, c.payload, c.result, c.issued_at, c.completed_at
		FROM agent_commands c JOIN agents a ON a.id = c.agent_id JOIN devices d ON d.id = a.device_id
		WHERE c.id = $1`, id).Scan(&v.CommandID, &v.DeviceID, &v.Type, &v.Status, &v.Payload, &result, &v.IssuedAt, &v.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "command not found", http.StatusNotFound)
		return
	}
	if err != nil {
		h.log.Error("agent action: status", "error", err.Error())
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	// A result can hold command output or file listings: reading it needs the
	// permission that sending that kind of command needs.
	caller, _ := apiauth.FromContext(r.Context())
	if perm := readPerm(v.Type); !caller.Can(perm) {
		apiauth.Deny(w, h.log, caller, perm, r)
		return
	}
	if len(result) > 0 {
		v.Result = result
	}
	writeJSON(w, http.StatusOK, v)
}

// readPerm is the permission needed to read a command's status and result.
func readPerm(cmdType string) string {
	if p, ok := permFor[cmdType]; ok {
		return p
	}
	switch {
	case cmdType == "install_patch" || cmdType == "stage_patch":
		return apiauth.PermPatchDeploy
	case strings.HasPrefix(cmdType, "software_deploy"):
		return apiauth.PermSoftwareDeploy
	case cmdType == "collect_file":
		return apiauth.PermFilesCollect
	case cmdType == "file_operation":
		return apiauth.PermFilesManage
	case cmdType == "open_shell":
		return apiauth.PermAgentShell
	}
	return apiauth.PermAgentCommand // run_command and anything else
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v) //nolint:errcheck // client went away
}
