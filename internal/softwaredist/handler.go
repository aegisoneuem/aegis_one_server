package softwaredist

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aegis-one/internal/apiauth"
)

// PackagesHandler serves /internal/software/packages (mount behind
// apiauth.Require(PermSoftwareDeploy)):
//
//	POST multipart/form-data: fields name, version, installer_type
//	     (msi|exe|ps1|bat|cmd|python|vbs), optional silent_args, product_code,
//	     uninstall_key, display_name, success_exit_codes ("0,1"),
//	     timeout_seconds, require_signature ("true"); and the installer as "file"
//	GET  -> all packages; GET ?id=<package_id> -> one
type PackagesHandler struct {
	store *Store
	log   *slog.Logger
}

func NewPackagesHandler(store *Store, log *slog.Logger) *PackagesHandler {
	return &PackagesHandler{store: store, log: log}
}

// maxFieldBytes caps one non-file form field.
const maxFieldBytes = 4 << 10

func (h *PackagesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.upload(w, r)
	case http.MethodGet:
		if id := r.URL.Query().Get("id"); id != "" {
			p, err := h.store.Get(r.Context(), id)
			if err != nil {
				h.log.Error("software packages: get", "error", err.Error())
				http.Error(w, "query failed", http.StatusInternalServerError)
				return
			}
			if p == nil {
				http.Error(w, "package not found", http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, p)
			return
		}
		list, err := h.store.List(r.Context())
		if err != nil {
			h.log.Error("software packages: list", "error", err.Error())
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
	}
}

func (h *PackagesHandler) upload(w http.ResponseWriter, r *http.Request) {
	caller, ok := apiauth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "multipart/form-data" {
		http.Error(w, "send multipart/form-data with a \"file\" part", http.StatusUnsupportedMediaType)
		return
	}
	// The file is streamed to disk, never held in memory; the body cap is the
	// file cap plus room for the form fields.
	r.Body = http.MaxBytesReader(w, r.Body, h.store.maxBytes+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "bad multipart body: "+err.Error(), http.StatusBadRequest)
		return
	}
	fields := map[string]string{}
	var staged *Staged
	defer func() { h.store.Discard(staged) }() // no-op after Commit consumed it
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			h.uploadError(w, err)
			return
		}
		name := part.FormName()
		if name == "file" {
			if staged != nil {
				http.Error(w, "only one file per package", http.StatusBadRequest)
				return
			}
			staged, err = h.store.Stage(part.FileName(), part)
			if err != nil {
				h.uploadError(w, err)
				return
			}
			continue
		}
		b, err := io.ReadAll(io.LimitReader(part, maxFieldBytes+1))
		if err != nil {
			h.uploadError(w, err)
			return
		}
		if len(b) > maxFieldBytes {
			http.Error(w, "form field "+name+" is too long", http.StatusBadRequest)
			return
		}
		fields[name] = string(b)
	}
	if staged == nil {
		http.Error(w, `the installer must be sent as the "file" part`, http.StatusBadRequest)
		return
	}

	meta, err := metaFromFields(fields)
	if err != nil {
		h.uploadError(w, err)
		return
	}
	if IsScript(strings.ToLower(strings.TrimSpace(meta.InstallerType))) && !caller.Can(apiauth.PermSoftwareScript) {
		http.Error(w, "uploading a script package needs the software.script permission", http.StatusForbidden)
		return
	}
	st := staged
	staged = nil
	p, err := h.store.Commit(r.Context(), meta, st, caller.ClientID, caller.ClientName)
	if err != nil {
		h.uploadError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *PackagesHandler) uploadError(w http.ResponseWriter, err error) {
	var ue *UserError
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &ue):
		http.Error(w, ue.Error(), http.StatusUnprocessableEntity)
	case errors.As(err, &tooBig):
		http.Error(w, "upload is larger than the server's limit (AEGIS_SOFTWARE_MAX_UPLOAD_BYTES)", http.StatusRequestEntityTooLarge)
	default:
		h.log.Error("software packages: upload", "error", err.Error())
		http.Error(w, "upload failed", http.StatusInternalServerError)
	}
}

func metaFromFields(f map[string]string) (Meta, error) {
	m := Meta{
		Name: f["name"], Version: f["version"], InstallerType: f["installer_type"], SilentArgs: f["silent_args"],
		ProductCode: f["product_code"], UninstallKey: f["uninstall_key"], DisplayName: f["display_name"],
	}
	if v := strings.TrimSpace(f["timeout_seconds"]); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return m, userErr("timeout_seconds must be a number")
		}
		m.TimeoutSeconds = int32(n)
	}
	if v := strings.TrimSpace(f["require_signature"]); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return m, userErr("require_signature must be true or false")
		}
		m.RequireSignature = b
	}
	for _, c := range strings.Split(f["success_exit_codes"], ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		n, err := strconv.ParseInt(c, 10, 32)
		if err != nil {
			return m, userErr("success_exit_codes must be comma-separated numbers")
		}
		m.SuccessExitCodes = append(m.SuccessExitCodes, int32(n))
	}
	return m, nil
}

// DeployHandler serves /internal/software/deploy (mount behind
// apiauth.Require(PermSoftwareDeploy)):
//
//	POST {"package_id": "...", "action": "install|uninstall", "device_ids": ["..."]}
//	     -> 202 + deployment id
//	GET  ?id=<deployment_id> -> per-device progress
type DeployHandler struct {
	d   *Deployer
	log *slog.Logger
}

func NewDeployHandler(d *Deployer, log *slog.Logger) *DeployHandler {
	return &DeployHandler{d: d, log: log}
}

func (h *DeployHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.create(w, r)
	case http.MethodGet:
		h.status(w, r)
	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
	}
}

func (h *DeployHandler) create(w http.ResponseWriter, r *http.Request) {
	caller, ok := apiauth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var body struct {
		PackageID string   `json:"package_id"`
		Action    string   `json:"action"`
		DeviceIDs []string `json:"device_ids"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "bad JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	out, err := h.d.Create(r.Context(), DeployRequest{
		PackageID: body.PackageID, Action: body.Action, DeviceIDs: body.DeviceIDs,
		ClientID: caller.ClientID, ClientName: caller.ClientName, CanScript: caller.Can(apiauth.PermSoftwareScript),
	})
	var ue *UserError
	var pe *PermissionError
	switch {
	case errors.As(err, &ue):
		http.Error(w, ue.Error(), http.StatusUnprocessableEntity)
	case errors.As(err, &pe):
		http.Error(w, pe.Error(), http.StatusForbidden)
	case err != nil:
		h.log.Error("software deploy: create", "error", err.Error())
		http.Error(w, "could not create deployment", http.StatusInternalServerError)
	default:
		writeJSON(w, http.StatusAccepted, out)
	}
}

type resultView struct {
	DeviceID       string     `json:"device_id"`
	Status         string     `json:"status"`
	Outcome        *string    `json:"outcome,omitempty"` // SUCCESS | NOT_APPLICABLE | FAILED (agent's final phase)
	ExitCode       *int32     `json:"exit_code,omitempty"`
	RebootRequired *bool      `json:"reboot_required,omitempty"`
	Error          *string    `json:"error,omitempty"`
	AgentReason    *string    `json:"agent_reason,omitempty"` // what the agent said, e.g. "not installed (nothing to uninstall)"
	CommandID      *string    `json:"command_id,omitempty"`
	AgentPhase     *string    `json:"agent_phase,omitempty"` // latest ActionStatus while running
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

func (h *DeployHandler) status(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !isUUID(id) {
		http.Error(w, "id (a deployment_id) is required", http.StatusBadRequest)
		return
	}
	var dep struct {
		Status, Action, Name, PackageID string
	}
	err := h.d.pool.QueryRow(r.Context(), `SELECT status, action, coalesce(name, ''), package_id::text FROM software_deployments WHERE id = $1`, id).
		Scan(&dep.Status, &dep.Action, &dep.Name, &dep.PackageID)
	if err != nil {
		http.Error(w, "deployment not found", http.StatusNotFound)
		return
	}
	rows, err := h.d.pool.Query(r.Context(), `
		SELECT dv.agent_reported_id, r.status, r.outcome, r.exit_code, r.reboot_required, r.error_message,
		       NULLIF(c.result->>'reason', ''), r.command_id::text, c.result->>'phase', r.started_at, r.completed_at
		FROM software_deployment_results r
		JOIN devices dv ON dv.id = r.device_id
		LEFT JOIN agent_commands c ON c.id = r.command_id
		WHERE r.deployment_id = $1 ORDER BY dv.agent_reported_id`, id)
	if err != nil {
		h.log.Error("software deploy: status", "error", err.Error())
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	results := []resultView{}
	counts := map[string]int{}
	for rows.Next() {
		var v resultView
		if err := rows.Scan(&v.DeviceID, &v.Status, &v.Outcome, &v.ExitCode, &v.RebootRequired, &v.Error,
			&v.AgentReason, &v.CommandID, &v.AgentPhase, &v.StartedAt, &v.CompletedAt); err != nil {
			h.log.Error("software deploy: status scan", "error", err.Error())
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		counts[v.Status]++
		results = append(results, v)
	}
	action := dep.Action
	if action == "remove" {
		action = "uninstall"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deployment_id": id, "name": dep.Name, "package_id": dep.PackageID, "action": action,
		"status": dep.Status, "counts": counts, "results": results,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v) //nolint:errcheck // client went away
}
