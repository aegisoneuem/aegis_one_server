package patchdeploy

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"aegis-one/internal/apiauth"
)

// Handler serves /internal/deploy (mount behind apiauth.Require(PermPatchDeploy)):
//
//	POST /internal/deploy?device_id=X&kb=KB5066835  start a push; 202 + the new ids
//	GET  /internal/deploy?id=<deployment_id>        per-device progress
type Handler struct {
	d   *Deployer
	log *slog.Logger
}

func NewHandler(d *Deployer, log *slog.Logger) *Handler { return &Handler{d: d, log: log} }

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
	q := r.URL.Query()
	if q.Get("device_id") == "" || q.Get("kb") == "" {
		http.Error(w, "device_id and kb are required", http.StatusBadRequest)
		return
	}
	out, err := h.d.Create(r.Context(), Request{DeviceID: q.Get("device_id"), KB: q.Get("kb"), ClientID: caller.ClientID, ClientName: caller.ClientName})
	var ue *UserError
	if errors.As(err, &ue) {
		http.Error(w, ue.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		h.log.Error("patch deploy: create", "error", err.Error())
		http.Error(w, "could not create deployment", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, out)
}

type resultView struct {
	ResultID     string     `json:"result_id"`
	DeviceID     string     `json:"device_id"`
	KB           string     `json:"kb"`
	Status       string     `json:"status"`
	Step         *string    `json:"step,omitempty"`
	File         *string    `json:"file,omitempty"`
	Download     *string    `json:"download_state,omitempty"`
	SkippedFiles []string   `json:"skipped_files,omitempty"`
	StageCmd     *string    `json:"stage_command_id,omitempty"`
	InstallCmd   *string    `json:"install_command_id,omitempty"`
	Error        *string    `json:"error,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !isUUID(id) {
		http.Error(w, "id (a deployment_id) is required", http.StatusBadRequest)
		return
	}
	var depStatus string
	err := h.d.pool.QueryRow(r.Context(), `SELECT status FROM patch_deployments WHERE id = $1`, id).Scan(&depStatus)
	if err != nil {
		http.Error(w, "deployment not found", http.StatusNotFound)
		return
	}
	rows, err := h.d.pool.Query(r.Context(), `
		SELECT r.id, dv.agent_reported_id, p.kb_or_advisory_id, r.status, r.step, pc.file_name, pc.state, r.skipped_files,
		       r.stage_command_id::text, r.install_command_id::text, r.error_message, r.started_at, r.completed_at
		FROM patch_deployment_results r
		JOIN devices dv ON dv.id = r.device_id
		JOIN patch_catalog p ON p.id = r.patch_id
		LEFT JOIN patch_content pc ON pc.file_digest = r.file_digest
		WHERE r.deployment_id = $1 ORDER BY dv.agent_reported_id`, id)
	if err != nil {
		h.log.Error("patch deploy: status", "error", err.Error())
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	results := []resultView{}
	for rows.Next() {
		var v resultView
		if err := rows.Scan(&v.ResultID, &v.DeviceID, &v.KB, &v.Status, &v.Step, &v.File, &v.Download, &v.SkippedFiles,
			&v.StageCmd, &v.InstallCmd, &v.Error, &v.StartedAt, &v.CompletedAt); err != nil {
			h.log.Error("patch deploy: status scan", "error", err.Error())
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		results = append(results, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"deployment_id": id, "status": depStatus, "results": results})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v) //nolint:errcheck // client went away
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
