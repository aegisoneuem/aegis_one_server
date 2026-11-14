package agentpolicy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"aegis-one/internal/apiauth"
)

const maxBody = 64 << 10

// Handler serves:
//
//	GET /internal/policy           current version, fleet counts, history (devices.view)
//	PUT /internal/policy           publish a new version and push it (agent.policy)
//	GET /internal/policy/devices   per-agent state, ?status=&limit= (devices.view)
type Handler struct {
	store  *Store
	pusher *Pusher
	log    *slog.Logger
}

func NewHandler(store *Store, pusher *Pusher, log *slog.Logger) *Handler {
	return &Handler{store: store, pusher: pusher, log: log}
}

// PublishRequest is the PUT body.
type PublishRequest struct {
	Policy json.RawMessage `json:"policy"`
	Note   string          `json:"note"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	caller, ok := apiauth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	need := apiauth.PermDevicesView
	if r.Method == http.MethodPut {
		need = apiauth.PermAgentPolicy
	}
	switch {
	case path == "/internal/policy" && (r.Method == http.MethodGet || r.Method == http.MethodPut),
		path == "/internal/policy/devices" && r.Method == http.MethodGet:
	default:
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !caller.Can(need) {
		apiauth.Deny(w, h.log, caller, need, r)
		return
	}
	switch {
	case path == "/internal/policy/devices":
		h.devices(w, r)
	case r.Method == http.MethodGet:
		h.get(w, r)
	default:
		h.publish(w, r, caller)
	}
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cur, err := h.store.Current(ctx)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := map[string]any{"current": cur}
	if cur != nil {
		counts, err := h.store.FleetCounts(ctx, cur.IssuedAt)
		if err != nil {
			h.fail(w, err)
			return
		}
		out["fleet"] = counts
	}
	hist, err := h.store.History(ctx, 20)
	if err != nil {
		h.fail(w, err)
		return
	}
	out["history"] = hist
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) publish(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > maxBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var req PublishRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Policy) == 0 {
		http.Error(w, `body must be {"policy": {...}, "note": "..."}`, http.StatusUnprocessableEntity)
		return
	}
	if len(req.Note) > 500 {
		http.Error(w, "note is limited to 500 characters", http.StatusUnprocessableEntity)
		return
	}
	doc, err := ParseRequest(req.Policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	pub, err := h.store.Publish(r.Context(), doc, strings.TrimSpace(req.Note), caller.ClientID, caller.ClientName)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.log.Info("agent policy published", "policy_id", pub.ID, "issued_at", pub.IssuedAt, "by", caller.ClientName)
	h.pusher.BroadcastAsync()
	writeJSON(w, http.StatusCreated, map[string]any{"published": pub, "push": "started for connected agents; others get it when they connect"})
}

func (h *Handler) devices(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "applied", "failed", "tampered":
	default:
		http.Error(w, "status must be one of pending, applied, failed, tampered", http.StatusUnprocessableEntity)
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			http.Error(w, "limit must be 1-1000", http.StatusUnprocessableEntity)
			return
		}
		limit = n
	}
	rows, err := h.store.Devices(r.Context(), status, limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": rows})
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	h.log.Error("agent policy API", "error", err.Error())
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck // client went away
}
