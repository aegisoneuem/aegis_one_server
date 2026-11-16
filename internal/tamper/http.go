package tamper

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aegis-one/internal/apiauth"
)

const maxBody = 16 << 10

// Handler serves (mounted behind apiauth.Require("")):
//
//	GET  /internal/tamper                         settings + fleet counts            devices.view
//	PUT  /internal/tamper/settings                change settings, push to fleet     agent.tamper
//	GET  /internal/tamper/devices?status=&limit=  per-device state                   devices.view
//	GET  /internal/tamper/devices/{id}            state, open alerts, agent events   devices.view
//	POST /internal/tamper/devices/{id}/reveal     show the passcode (audited)        agent.tamper.reveal
//	POST /internal/tamper/devices/{id}/token      break-glass token, {"ttl_minutes"} agent.tamper.reveal
//	POST /internal/tamper/devices/{id}/rotate     new passcode now                   agent.tamper
//	POST /internal/tamper/devices/{id}/stop       stop the agent (token command)     agent.tamper
type Handler struct {
	svc *Service
	log *slog.Logger
}

func NewHandler(svc *Service, log *slog.Logger) *Handler { return &Handler{svc: svc, log: log} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	caller, ok := apiauth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	rest, isDevice := strings.CutPrefix(path, "/internal/tamper/devices/")
	deviceID, action, _ := strings.Cut(rest, "/")

	var need string
	var serve func()
	switch {
	case path == "/internal/tamper" && r.Method == http.MethodGet:
		need, serve = apiauth.PermDevicesView, func() { h.get(w, r) }
	case path == "/internal/tamper/settings" && r.Method == http.MethodPut:
		need, serve = apiauth.PermAgentTamper, func() { h.putSettings(w, r, caller) }
	case path == "/internal/tamper/devices" && r.Method == http.MethodGet:
		need, serve = apiauth.PermDevicesView, func() { h.devices(w, r) }
	case isDevice && deviceID != "" && action == "" && r.Method == http.MethodGet:
		need, serve = apiauth.PermDevicesView, func() { h.device(w, r, deviceID) }
	case isDevice && deviceID != "" && action == "reveal" && r.Method == http.MethodPost:
		need, serve = apiauth.PermAgentTamperReveal, func() { h.reveal(w, r, caller, deviceID) }
	case isDevice && deviceID != "" && action == "token" && r.Method == http.MethodPost:
		need, serve = apiauth.PermAgentTamperReveal, func() { h.token(w, r, caller, deviceID) }
	case isDevice && deviceID != "" && action == "rotate" && r.Method == http.MethodPost:
		need, serve = apiauth.PermAgentTamper, func() { h.rotate(w, r, deviceID) }
	case isDevice && deviceID != "" && action == "stop" && r.Method == http.MethodPost:
		need, serve = apiauth.PermAgentTamper, func() { h.stop(w, r, caller, deviceID) }
	default:
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !caller.Can(need) {
		apiauth.Deny(w, h.log, caller, need, r)
		return
	}
	// Responses carry passcodes/tokens: never cache them anywhere.
	w.Header().Set("Cache-Control", "no-store")
	serve()
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	st, err := LoadSettings(r.Context(), h.svc.pool)
	if err != nil {
		h.fail(w, err)
		return
	}
	counts, err := h.svc.FleetCounts(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": st, "counts": counts})
}

func (h *Handler) putSettings(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	cur, err := LoadSettings(r.Context(), h.svc.pool)
	if err != nil {
		h.fail(w, err)
		return
	}
	// Partial update: fields left out keep their current value.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	next := cur
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := next.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := h.svc.SaveSettings(r.Context(), next, caller.ClientID, caller.ClientName); err != nil {
		h.fail(w, err)
		return
	}
	h.log.Info("tamper settings changed", "client", caller.ClientName, "enabled", next.Enabled,
		"rotation_days", next.RotationDays, "max_tries", next.MaxTries)
	// max_tries is part of the passcode command: a change reaches agents with
	// their next passcode (rotation), not by itself.
	if next.Enabled != cur.Enabled {
		h.svc.BroadcastAsync()
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": next, "pushing": next.Enabled != cur.Enabled})
}

func (h *Handler) devices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	switch status {
	case "", "applied", "pending", "failed", "cleared", "not_provisioned":
	default:
		http.Error(w, "status must be one of applied, pending, failed, cleared, not_provisioned", http.StatusUnprocessableEntity)
		return
	}
	limit := 200
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			http.Error(w, "limit must be 1..5000", http.StatusUnprocessableEntity)
			return
		}
		limit = n
	}
	out, err := h.svc.Devices(r.Context(), status, limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (h *Handler) device(w http.ResponseWriter, r *http.Request, deviceID string) {
	out, err := h.svc.Device(r.Context(), deviceID)
	if h.deviceErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) reveal(w http.ResponseWriter, r *http.Request, caller apiauth.Principal, deviceID string) {
	out, err := h.svc.Reveal(r.Context(), deviceID, caller.ClientID, caller.ClientName)
	if h.deviceErr(w, err) {
		return
	}
	h.log.Warn("unprotect passcode revealed", "client", caller.ClientName, "device_id", deviceID)
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request, caller apiauth.Principal, deviceID string) {
	var body struct {
		TTLMinutes int `json:"ttl_minutes"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	ttl := DefaultTokenTTL
	if body.TTLMinutes != 0 {
		if body.TTLMinutes < 1 || time.Duration(body.TTLMinutes)*time.Minute > MaxTokenTTL {
			http.Error(w, "ttl_minutes must be 1..1440", http.StatusUnprocessableEntity)
			return
		}
		ttl = time.Duration(body.TTLMinutes) * time.Minute
	}
	tok, err := h.svc.IssueToken(r.Context(), deviceID, ttl, caller.ClientID, caller.ClientName)
	if h.deviceErr(w, err) {
		return
	}
	h.log.Warn("unprotect token issued", "client", caller.ClientName, "device_id", deviceID, "expires_at", tok.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"token": tok.Token, "device_id": tok.DeviceID, "expires_at": tok.ExpiresAt,
		"usage": "AegisOneClient.exe stop --token <token>  |  msiexec /x AegisOneClient.msi UNINSTALLPASSCODE=<token> /qn"})
}

func (h *Handler) rotate(w http.ResponseWriter, r *http.Request, deviceID string) {
	status, err := h.svc.Push(r.Context(), deviceID, true, "manual rotation")
	if errors.Is(err, ErrDisabled) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	if status == "unknown_device" {
		http.Error(w, ErrUnknownDevice.Error(), http.StatusNotFound)
		return
	}
	// offline: the new passcode is pending and goes out on the next connect;
	// until then the agent keeps (and accepts) the old one.
	writeJSON(w, http.StatusAccepted, map[string]any{"device_id": deviceID, "status": status})
}

func (h *Handler) stop(w http.ResponseWriter, r *http.Request, caller apiauth.Principal, deviceID string) {
	sent, err := h.svc.Stop(r.Context(), deviceID, caller.ClientID, caller.ClientName)
	if h.deviceErr(w, err) {
		return
	}
	h.log.Warn("stop_agent issued", "client", caller.ClientName, "device_id", deviceID, "status", sent.Status)
	code := http.StatusAccepted
	if sent.Status != "dispatched" {
		code = http.StatusConflict // offline / failed: nothing was sent
	}
	writeJSON(w, code, sent)
}

// deviceErr writes 404 for an unknown device and 500 otherwise; true if it wrote.
func (h *Handler) deviceErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrUnknownDevice):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		h.fail(w, err)
	}
	return true
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	h.log.Error("tamper api failed", "error", err.Error())
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
