package remoteops

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/apiauth"
	"aegis-one/internal/commands"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// Handler serves /internal/remote/ (mount behind apiauth.Require(""); each
// route checks its own permission):
//
//	POST /internal/remote/collect          collect_file          files.collect
//	GET  /internal/remote/uploads?command_id=  list uploads       files.collect
//	GET  /internal/remote/uploads/download?id= one file           files.collect
//	POST /internal/remote/run              run_command (SYSTEM)  agent.command
//	POST /internal/remote/files            file_operation        files.manage
//	     {device_ids, operation: mkdir|touch|delete|list_directory (path),
//	      write_bytes (destination, content_base64, append), copy|move on the
//	      same device (source, destination, destination_dir), recursive, overwrite}
//	POST /internal/remote/transfers        copy / move between endpoints  files.manage
//	GET  /internal/remote/transfers?id=
//	POST /internal/remote/shell            open a shell          agent.shell
//	POST /internal/remote/shell/input      {session_id, stdin | stdin_base64, control}
//	GET  /internal/remote/shell/output?session_id=&after=&wait_seconds=
//	GET  /internal/remote/shell/transcript?session_id=
//
// Command results: GET /internal/actions?command_id=.
type Handler struct {
	pool      *pgxpool.Pool
	sender    *commands.Sender
	uploads   *Uploads
	transfers *Transfers
	shells    *Shells
	log       *slog.Logger
}

func NewHandler(pool *pgxpool.Pool, sender *commands.Sender, uploads *Uploads, transfers *Transfers, shells *Shells, log *slog.Logger) *Handler {
	return &Handler{pool: pool, sender: sender, uploads: uploads, transfers: transfers, shells: shells, log: log}
}

// UserError is a request the caller can fix.
type UserError struct{ msg string }

func (e *UserError) Error() string { return e.msg }

func userErr(format string, a ...any) error { return &UserError{fmt.Sprintf(format, a...)} }

const maxDevices = 1000

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	caller, ok := apiauth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	route := strings.TrimPrefix(r.URL.Path, "/internal/remote/")
	need := map[string]string{
		"collect": apiauth.PermFilesCollect, "uploads": apiauth.PermFilesCollect, "uploads/download": apiauth.PermFilesCollect,
		"run": apiauth.PermAgentCommand, "files": apiauth.PermFilesManage, "transfers": apiauth.PermFilesManage,
		"shell": apiauth.PermAgentShell, "shell/input": apiauth.PermAgentShell, "shell/output": apiauth.PermAgentShell,
		"shell/transcript": apiauth.PermAgentShell,
	}[route]
	if need == "" {
		http.NotFound(w, r)
		return
	}
	if !caller.Can(need) {
		apiauth.Deny(w, h.log, caller, need, r)
		return
	}
	switch {
	case route == "collect" && r.Method == http.MethodPost:
		h.collect(w, r, caller)
	case route == "uploads" && r.Method == http.MethodGet:
		h.listUploads(w, r)
	case route == "uploads/download" && r.Method == http.MethodGet:
		h.download(w, r)
	case route == "run" && r.Method == http.MethodPost:
		h.run(w, r, caller)
	case route == "files" && r.Method == http.MethodPost:
		h.files(w, r, caller)
	case route == "transfers" && r.Method == http.MethodPost:
		h.createTransfer(w, r, caller)
	case route == "transfers" && r.Method == http.MethodGet:
		h.viewTransfer(w, r)
	case route == "shell" && r.Method == http.MethodPost:
		h.openShell(w, r, caller)
	case route == "shell/input" && r.Method == http.MethodPost:
		h.shellInput(w, r, caller)
	case route == "shell/output" && r.Method == http.MethodGet:
		h.shellOutput(w, r, caller)
	case route == "shell/transcript" && r.Method == http.MethodGet:
		h.shellTranscript(w, r, caller)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// fanOut sends one command to each device and writes the per-device results.
func (h *Handler) fanOut(w http.ResponseWriter, r *http.Request, caller apiauth.Principal, devices []string, cmdType string,
	wire []byte, audit map[string]any) {
	devices = dedupe(devices)
	if len(devices) == 0 || len(devices) > maxDevices {
		http.Error(w, fmt.Sprintf("device_ids: 1..%d devices", maxDevices), http.StatusUnprocessableEntity)
		return
	}
	results := make([]commands.Sent, 0, len(devices))
	counts := map[string]int{}
	for _, dev := range devices {
		sent, err := h.sender.Send(r.Context(), commands.SendRequest{DeviceID: dev, Type: cmdType, Wire: wire, Audit: audit,
			ClientID: caller.ClientID, ClientName: caller.ClientName, Actor: "api_client:" + caller.ClientName})
		if err != nil {
			h.log.Error("remote op: send", "type", cmdType, "device_id", dev, "error", err.Error())
			sent = commands.Sent{DeviceID: dev, Status: "failed", Error: "server error"}
		}
		counts[sent.Status]++
		results = append(results, sent)
	}
	h.log.Info("remote op sent", "type", cmdType, "devices", len(devices), "dispatched", counts["dispatched"], "client", caller.ClientName)
	writeJSON(w, http.StatusAccepted, map[string]any{"type": cmdType, "counts": counts, "results": results})
}

func (h *Handler) collect(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	var body struct {
		DeviceIDs               []string `json:"device_ids"`
		Paths                   []string `json:"paths"`
		MaxBytesEach            int64    `json:"max_bytes_each"`
		TailBytes               int64    `json:"tail_bytes"`
		MaxTotalBytes           int64    `json:"max_total_bytes"`
		MaxUploadBytesPerSecond int64    `json:"max_upload_bytes_per_second"`
	}
	if !decode(w, r, &body, 1<<20) {
		return
	}
	if len(body.Paths) == 0 || len(body.Paths) > 32 {
		http.Error(w, "paths: 1..32 paths (globs allowed)", http.StatusUnprocessableEntity)
		return
	}
	for _, p := range body.Paths {
		if err := checkPath("paths", p); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}
	for name, v := range map[string]int64{"max_bytes_each": body.MaxBytesEach, "tail_bytes": body.TailBytes,
		"max_total_bytes": body.MaxTotalBytes, "max_upload_bytes_per_second": body.MaxUploadBytesPerSecond} {
		if v < 0 || v > collectHardTotal {
			http.Error(w, name+" must be 0..2 GiB", http.StatusUnprocessableEntity)
			return
		}
	}
	wire, _ := proto.Marshal(&aegisonev1.CollectFileSpec{Paths: body.Paths, MaxBytesEach: body.MaxBytesEach,
		TailBytes: body.TailBytes, MaxTotalBytes: body.MaxTotalBytes, MaxUploadBytesPerSecond: body.MaxUploadBytesPerSecond})
	h.fanOut(w, r, caller, body.DeviceIDs, "collect_file", wire, map[string]any{"paths": body.Paths,
		"max_bytes_each": body.MaxBytesEach, "tail_bytes": body.TailBytes, "max_total_bytes": body.MaxTotalBytes,
		"max_upload_bytes_per_second": body.MaxUploadBytesPerSecond})
}

func (h *Handler) listUploads(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("command_id")
	if !commands.IsCommandID(id) {
		http.Error(w, "command_id is required", http.StatusBadRequest)
		return
	}
	list, err := h.uploads.list(r.Context(), id)
	if err != nil {
		h.log.Error("uploads: list", "error", err.Error())
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *Handler) download(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !commands.IsCommandID(id) {
		http.Error(w, "id (an upload_id) is required", http.StatusBadRequest)
		return
	}
	up, err := h.uploads.get(r.Context(), id)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	if up == nil {
		http.Error(w, "upload not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(h.uploads.path(up))
	if err != nil {
		http.Error(w, "file is no longer on the server", http.StatusGone)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+up.Name+`"`)
	w.Header().Set("X-Content-SHA256", up.SHA256)
	w.Header().Set("Content-Length", strconv.FormatInt(up.SizeBytes, 10))
	http.ServeContent(w, r, up.Name, time.Time{}, f)
}

func (h *Handler) run(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	var body struct {
		DeviceIDs      []string          `json:"device_ids"`
		Command        string            `json:"command"`
		Shell          string            `json:"shell"`
		TimeoutSeconds int32             `json:"timeout_seconds"`
		MaxOutputBytes int64             `json:"max_output_bytes"`
		WorkingDir     string            `json:"working_dir"`
		Parameters     map[string]string `json:"parameters"`
		UploadOutput   bool              `json:"upload_output"`
	}
	if !decode(w, r, &body, 1<<20) {
		return
	}
	body.Shell = strings.ToLower(strings.TrimSpace(body.Shell))
	switch {
	case strings.TrimSpace(body.Command) == "" || len(body.Command) > 64<<10:
		http.Error(w, "command is required (at most 64 KiB)", http.StatusUnprocessableEntity)
		return
	case body.Shell != "" && body.Shell != "cmd" && body.Shell != "powershell" && body.Shell != "pwsh":
		http.Error(w, "shell must be cmd, powershell or pwsh", http.StatusUnprocessableEntity)
		return
	case body.TimeoutSeconds < 0 || body.TimeoutSeconds > 3600:
		http.Error(w, "timeout_seconds must be 0..3600 (0 = agent default 300)", http.StatusUnprocessableEntity)
		return
	case body.MaxOutputBytes < 0 || body.MaxOutputBytes > 100<<20:
		http.Error(w, "max_output_bytes must be 0..100 MiB (0 = agent default 1 MiB)", http.StatusUnprocessableEntity)
		return
	case len(body.Parameters) > 64:
		http.Error(w, "at most 64 parameters", http.StatusUnprocessableEntity)
		return
	}
	if body.WorkingDir != "" {
		if err := checkPath("working_dir", body.WorkingDir); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}
	spec := &aegisonev1.RunCommandSpec{Command: body.Command, Shell: body.Shell, TimeoutSeconds: body.TimeoutSeconds,
		MaxOutputBytes: body.MaxOutputBytes, WorkingDir: body.WorkingDir, Parameters: body.Parameters}
	if body.UploadOutput {
		spec.UploadAs = "run_command-output.txt"
	}
	wire, _ := proto.Marshal(spec)
	h.fanOut(w, r, caller, body.DeviceIDs, "run_command", wire, map[string]any{"command": body.Command, "shell": body.Shell,
		"timeout_seconds": body.TimeoutSeconds, "max_output_bytes": body.MaxOutputBytes, "working_dir": body.WorkingDir,
		"parameters": body.Parameters, "upload_as": spec.UploadAs})
}

func (h *Handler) files(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	var body struct {
		DeviceIDs      []string `json:"device_ids"`
		Operation      string   `json:"operation"`
		Path           string   `json:"path"` // mkdir, touch, delete, list_directory
		Source         string   `json:"source"`
		Destination    string   `json:"destination"`
		Recursive      bool     `json:"recursive"`
		Overwrite      bool     `json:"overwrite"`
		DestinationDir bool     `json:"destination_dir"`
		MaxFiles       int      `json:"max_files"`
		ContentBase64  string   `json:"content_base64"`
		Append         bool     `json:"append"`
	}
	if !decode(w, r, &body, 16<<20) {
		return
	}
	op := strings.ToLower(strings.TrimSpace(body.Operation))
	spec := fileSpec{Version: 1, Operation: op, Recursive: body.Recursive, Overwrite: body.Overwrite,
		DestinationDir: body.DestinationDir, MaxFiles: body.MaxFiles}
	audit := map[string]any{"operation": op, "recursive": body.Recursive, "overwrite": body.Overwrite}
	var err error
	switch op {
	case "mkdir", "touch", "delete", "list_directory":
		// The agent takes the path of these in "source".
		err = checkPath("path", body.Path)
		spec.Source, audit["path"] = body.Path, body.Path
		if op == "list_directory" && (body.MaxFiles < 0 || body.MaxFiles > 10000) {
			err = userErr("max_files must be 0..10000")
		}
	case "copy", "move": // on the same device; across devices use /internal/remote/transfers
		if err = checkPath("source", body.Source); err == nil {
			err = checkPath("destination", body.Destination)
		}
		spec.Source, spec.Destination = body.Source, body.Destination
		audit["source"], audit["destination"] = body.Source, body.Destination
	case "write_bytes":
		if err = checkPath("destination", body.Destination); err == nil {
			spec.Content, err = base64.StdEncoding.DecodeString(body.ContentBase64)
			if err != nil {
				err = userErr("content_base64 is not valid base64")
			} else if len(spec.Content) > 10<<20 {
				err = userErr("write_bytes content is limited to 10 MiB through the API")
			}
		}
		spec.Destination, spec.Append = body.Destination, body.Append
		audit["destination"], audit["append"], audit["content_bytes"] = body.Destination, body.Append, len(spec.Content)
	default:
		err = userErr("operation must be mkdir, touch, delete, list_directory, write_bytes, copy or move")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	wire, _ := json.Marshal(spec)
	h.fanOut(w, r, caller, body.DeviceIDs, "file_operation", wire, audit)
}

func (h *Handler) createTransfer(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	var body TransferRequest
	if !decode(w, r, &body, 1<<20) {
		return
	}
	id, err := h.transfers.Create(r.Context(), body, caller.ClientID, caller.ClientName)
	if !h.userError(w, err) {
		writeJSON(w, http.StatusAccepted, map[string]any{"transfer_id": id})
	}
}

func (h *Handler) viewTransfer(w http.ResponseWriter, r *http.Request) {
	v, err := h.transfers.View(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	if v == nil {
		http.Error(w, "transfer not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) openShell(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	var body struct {
		DeviceID           string `json:"device_id"`
		TTLSeconds         int32  `json:"ttl_seconds"`
		IdleTimeoutSeconds int32  `json:"idle_timeout_seconds"`
		MaxDurationSeconds int32  `json:"max_duration_seconds"`
	}
	if !decode(w, r, &body, 1<<16) {
		return
	}
	out, err := h.shells.Open(r.Context(), OpenRequest{DeviceID: body.DeviceID, ClientID: caller.ClientID, ClientName: caller.ClientName,
		TTLSeconds: body.TTLSeconds, IdleTimeoutSeconds: body.IdleTimeoutSeconds, MaxDurationSeconds: body.MaxDurationSeconds})
	if !h.userError(w, err) {
		writeJSON(w, http.StatusAccepted, out)
	}
}

func (h *Handler) shellInput(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	var body struct {
		SessionID   string `json:"session_id"`
		Stdin       string `json:"stdin"`
		StdinBase64 string `json:"stdin_base64"`
		Control     string `json:"control"`
	}
	if !decode(w, r, &body, 128<<10) {
		return
	}
	in := []byte(body.Stdin)
	if body.StdinBase64 != "" {
		b, err := base64.StdEncoding.DecodeString(body.StdinBase64)
		if err != nil {
			http.Error(w, "stdin_base64 is not valid base64", http.StatusUnprocessableEntity)
			return
		}
		in = append(in, b...)
	}
	err := h.shells.Input(body.SessionID, caller.ClientID, in, body.Control)
	if !h.userError(w, err) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func (h *Handler) shellOutput(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	q := r.URL.Query()
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	wait, _ := strconv.Atoi(q.Get("wait_seconds"))
	v, err := h.shells.Output(r.Context(), q.Get("session_id"), caller.ClientID, after, time.Duration(wait)*time.Second)
	if !h.userError(w, err) {
		writeJSON(w, http.StatusOK, v)
	}
}

func (h *Handler) shellTranscript(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	id := r.URL.Query().Get("session_id")
	var name string
	err := h.pool.QueryRow(r.Context(), `SELECT transcript_name FROM shell_sessions WHERE id = $1 AND created_by_api_client_id = $2`,
		id, caller.ClientID).Scan(&name)
	if err != nil {
		http.Error(w, "no such session for this API client", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeFile(w, r, filepath.Join(h.uploads.dir, filepath.FromSlash(name)))
}

// userError writes a 4xx for a UserError / missing session and a 500 for
// anything else; it returns false when err is nil.
func (h *Handler) userError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var ue *UserError
	switch {
	case errors.As(err, &ue):
		http.Error(w, ue.Error(), http.StatusUnprocessableEntity)
	case errors.Is(err, errNoSession):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		h.log.Error("remote op", "error", err.Error())
		http.Error(w, "server error", http.StatusInternalServerError)
	}
	return true
}

// checkPath accepts an endpoint path (Windows or relative, globs allowed):
// non-empty, at most 1024 bytes, no control characters.
func checkPath(field, p string) error {
	if strings.TrimSpace(p) == "" {
		return userErr("%s is required", field)
	}
	if len(p) > 1024 {
		return userErr("%s is longer than 1024 bytes", field)
	}
	for _, c := range p {
		if unicode.IsControl(c) {
			return userErr("%s contains control characters", field)
		}
	}
	return nil
}

func decode(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "bad JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v) //nolint:errcheck // client went away
}
