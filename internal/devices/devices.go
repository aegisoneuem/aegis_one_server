// Package devices is the device lifecycle API:
//
//	GET  /internal/devices?state=&q=&limit=&after=   list (devices.view)
//	GET  /internal/devices?id=<device_id>            one device (devices.view)
//	GET  /internal/devices/summary                   count per state (devices.view)
//	POST /internal/devices/retire                    {"device_ids": [...], "reason": "..."} (devices.manage)
//	GET  /internal/devices/duplicates?status=         possible duplicates (devices.view)
//	POST /internal/devices/duplicates/confirm        {"id": "...", "reason": "..."} (devices.manage)
//	POST /internal/devices/duplicates/reject         {"id": "...", "reason": "..."} (devices.manage)
//
// State is derived from devices.status and last_seen_at (see 0021, 0023):
// merged, retired, unmanaged, online, offline, stale. "stale_alert" marks a
// device with no heartbeat for device.stale_alert_days (60); nothing is ever
// deleted. "connected" says whether the agent has a live stream right now.
//
// Retiring revokes the device's agent and certificates, fails its open
// commands, ends its live stream and writes audit_log. Nothing is deleted. A
// retired device comes back only by enrolling again with a token.
package devices

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"aegis-one/internal/apiauth"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// MaxRetire caps one retire request.
	MaxRetire = 1000
	// DefaultLimit and MaxLimit bound one list page.
	DefaultLimit = 100
	MaxLimit     = 1000
	// MaxReason is the longest retire reason accepted.
	MaxReason = 256
)

// States a device can be in.
var States = []string{"online", "offline", "stale", "retired", "merged", "unmanaged"}

// Live is the gRPC server's view of connected agents.
type Live interface {
	Connected(deviceID string) bool
	Disconnect(deviceID string) bool
}

type Handler struct {
	pool *pgxpool.Pool
	live Live
	log  *slog.Logger
}

func New(pool *pgxpool.Pool, live Live, log *slog.Logger) *Handler {
	return &Handler{pool: pool, live: live, log: log}
}

// Device is one row of the list and the detail view.
type Device struct {
	DeviceID      string     `json:"device_id"`
	Hostname      string     `json:"hostname"`
	OSFamily      string     `json:"os_family"`
	OSBuild       *string    `json:"os_build,omitempty"`
	AgentVersion  *string    `json:"agent_version,omitempty"`
	State         string     `json:"state"`
	Connected     bool       `json:"connected"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	FirstSeenAt   time.Time  `json:"first_seen_at"`
	RetiredAt     *time.Time `json:"retired_at,omitempty"`
	RetiredReason *string    `json:"retired_reason,omitempty"`
	RetiredBy     *string    `json:"retired_by,omitempty"`
	StaleAlert    bool       `json:"stale_alert,omitempty"`
	MergedInto    *string    `json:"merged_into_device_id,omitempty"`
	// Detail view only.
	AgentEnrolledAt *time.Time `json:"agent_enrolled_at,omitempty"`
	CertExpiresAt   *time.Time `json:"certificate_expires_at,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	caller, ok := apiauth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch {
	case path == "/internal/devices" && r.Method == http.MethodGet:
		if !caller.Can(apiauth.PermDevicesView) {
			apiauth.Deny(w, h.log, caller, apiauth.PermDevicesView, r)
			return
		}
		if id := r.URL.Query().Get("id"); id != "" {
			h.one(w, r, id)
			return
		}
		h.list(w, r)
	case path == "/internal/devices/summary" && r.Method == http.MethodGet:
		if !caller.Can(apiauth.PermDevicesView) {
			apiauth.Deny(w, h.log, caller, apiauth.PermDevicesView, r)
			return
		}
		h.summary(w, r)
	case path == "/internal/devices/retire" && r.Method == http.MethodPost:
		if !caller.Can(apiauth.PermDevicesManage) {
			apiauth.Deny(w, h.log, caller, apiauth.PermDevicesManage, r)
			return
		}
		h.retire(w, r, caller)
	case path == "/internal/devices/duplicates" && r.Method == http.MethodGet:
		if !caller.Can(apiauth.PermDevicesView) {
			apiauth.Deny(w, h.log, caller, apiauth.PermDevicesView, r)
			return
		}
		h.duplicates(w, r)
	case (path == "/internal/devices/duplicates/confirm" || path == "/internal/devices/duplicates/reject") && r.Method == http.MethodPost:
		if !caller.Can(apiauth.PermDevicesManage) {
			apiauth.Deny(w, h.log, caller, apiauth.PermDevicesManage, r)
			return
		}
		h.decide(w, r, caller, strings.HasSuffix(path, "/confirm"))
	case path == "/internal/devices" || path == "/internal/devices/summary" || path == "/internal/devices/retire" ||
		path == "/internal/devices/duplicates" || path == "/internal/devices/duplicates/confirm" || path == "/internal/devices/duplicates/reject":
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	default:
		http.NotFound(w, r)
	}
}

// thresholds reads the two settings that split online/offline/stale.
type thresholds struct {
	onlineSince, staleBefore time.Time
}

func (h *Handler) thresholds(ctx context.Context) (thresholds, error) {
	var mins, days int
	err := h.pool.QueryRow(ctx,
		`SELECT setting_int('agent.offline_after_minutes', 15), setting_int('device.stale_after_days', 30)`).Scan(&mins, &days)
	if err != nil {
		return thresholds{}, err
	}
	now := time.Now()
	return thresholds{onlineSince: now.Add(-time.Duration(mins) * time.Minute), staleBefore: now.AddDate(0, 0, -days)}, nil
}

// stateSQL is the state expression; $1 = online since, $2 = stale before.
const stateSQL = `CASE
	WHEN d.merged_into_device_id IS NOT NULL THEN 'merged'
	WHEN d.status = 'decommissioned' THEN 'retired'
	WHEN d.status = 'unmanaged' THEN 'unmanaged'
	WHEN d.last_seen_at >= $1 THEN 'online'
	WHEN d.last_seen_at >= $2 THEN 'offline'
	ELSE 'stale' END`

// stateWhere is the index-friendly filter for one state, same parameters.
var stateWhere = map[string]string{
	"retired":     `d.status = 'decommissioned' AND d.merged_into_device_id IS NULL`,
	"merged":      `d.merged_into_device_id IS NOT NULL`,
	"stale_alert": staleAlertSQL,
	"unmanaged":   `d.status = 'unmanaged'`,
	"online":      `d.status = 'active' AND d.last_seen_at >= $1`,
	"offline":     `d.status = 'active' AND d.last_seen_at < $1 AND d.last_seen_at >= $2`,
	"stale":       `d.status = 'active' AND (d.last_seen_at < $2 OR d.last_seen_at IS NULL)`,
}

// staleAlertSQL flags an active device silent for device.stale_alert_days
// (never seen: since it was first seen).
const staleAlertSQL = `(d.status = 'active' AND coalesce(d.last_seen_at, d.first_seen_at) < now() - make_interval(days => setting_int('device.stale_alert_days', 60)))`

// idSQL is the device_id shown; agentless devices have no agent_reported_id.
const idSQL = `coalesce(d.agent_reported_id, d.id::text)`

const selectSQL = `
	SELECT ` + idSQL + `, d.hostname, d.os_family,
	       CASE WHEN d.os_build IS NULL THEN NULL WHEN d.os_ubr IS NULL THEN d.os_build ELSE d.os_build || '.' || d.os_ubr END,
	       a.agent_version, ` + stateSQL + `, d.last_seen_at, d.first_seen_at, d.retired_at, d.retired_reason, d.retired_by,
	       ` + staleAlertSQL + `, (SELECT coalesce(m.agent_reported_id, m.id::text) FROM devices m WHERE m.id = d.merged_into_device_id),
	       a.enrolled_at, a.cert_not_after
	FROM devices d
	LEFT JOIN LATERAL (
		SELECT ag.agent_version, ag.enrolled_at,
		       (SELECT max(ac.not_after) FROM agent_certificates ac WHERE ac.agent_id = ag.id AND ac.revoked_at IS NULL) AS cert_not_after
		FROM agents ag WHERE ag.device_id = d.id ORDER BY ag.revoked_at IS NULL DESC, ag.enrolled_at DESC LIMIT 1
	) a ON true`

func scanDevice(row pgx.Row) (*Device, error) {
	var d Device
	err := row.Scan(&d.DeviceID, &d.Hostname, &d.OSFamily, &d.OSBuild, &d.AgentVersion, &d.State, &d.LastSeenAt,
		&d.FirstSeenAt, &d.RetiredAt, &d.RetiredReason, &d.RetiredBy, &d.StaleAlert, &d.MergedInto, &d.AgentEnrolledAt, &d.CertExpiresAt)
	return &d, err
}

// cursor is the keyset position of the last row of a page.
type cursor struct {
	Hostname string `json:"h"`
	DeviceID string `json:"d"`
}

func (c cursor) encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	var c cursor
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err != nil || c.DeviceID == "" {
		return cursor{}, errors.New("after: not a cursor from a previous page")
	}
	return c, nil
}

// escapeLike makes q a literal prefix for LIKE ... ESCAPE '\'.
func escapeLike(q string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	state := strings.ToLower(strings.TrimSpace(qs.Get("state")))
	if state != "" && state != "all" && stateWhere[state] == "" {
		http.Error(w, "state must be one of "+strings.Join(States, ", ")+", stale_alert or all", http.StatusUnprocessableEntity)
		return
	}
	limit := DefaultLimit
	if v := qs.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxLimit {
			http.Error(w, fmt.Sprintf("limit: 1..%d", MaxLimit), http.StatusUnprocessableEntity)
			return
		}
		limit = n
	}
	q := strings.TrimSpace(qs.Get("q"))
	if len(q) > 255 {
		http.Error(w, "q: at most 255 characters", http.StatusUnprocessableEntity)
		return
	}
	th, err := h.thresholds(r.Context())
	if err != nil {
		h.fail(w, "devices: thresholds", err)
		return
	}

	args := []any{th.onlineSince, th.staleBefore}
	where := []string{"true"}
	if s := stateWhere[state]; s != "" {
		where = append(where, s)
	}
	if q != "" {
		args = append(args, escapeLike(strings.ToLower(q))+"%", q)
		where = append(where, fmt.Sprintf(`(lower(d.hostname) LIKE $%d ESCAPE '\' OR d.agent_reported_id = $%d)`, len(args)-1, len(args)))
	}
	if a := qs.Get("after"); a != "" {
		c, err := decodeCursor(a)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		args = append(args, c.Hostname, c.DeviceID)
		where = append(where, fmt.Sprintf(`(d.hostname, `+idSQL+`) > ($%d, $%d)`, len(args)-1, len(args)))
	}
	args = append(args, limit+1)
	sql := selectSQL + " WHERE " + strings.Join(where, " AND ") +
		fmt.Sprintf(" ORDER BY d.hostname, "+idSQL+" LIMIT $%d", len(args))

	rows, err := h.pool.Query(r.Context(), sql, args...)
	if err != nil {
		h.fail(w, "devices: list", err)
		return
	}
	defer rows.Close()
	out := make([]*Device, 0, limit)
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			h.fail(w, "devices: scan", err)
			return
		}
		d.AgentEnrolledAt, d.CertExpiresAt = nil, nil
		d.Connected = d.DeviceID != "" && h.live.Connected(d.DeviceID)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		h.fail(w, "devices: list", err)
		return
	}
	resp := map[string]any{"devices": out}
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		resp["devices"] = out
		resp["next_after"] = cursor{Hostname: last.Hostname, DeviceID: last.DeviceID}.encode()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) one(w http.ResponseWriter, r *http.Request, id string) {
	th, err := h.thresholds(r.Context())
	if err != nil {
		h.fail(w, "devices: thresholds", err)
		return
	}
	d, err := scanDevice(h.pool.QueryRow(r.Context(), selectSQL+" WHERE "+idSQL+" = $3", th.onlineSince, th.staleBefore, id))
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "unknown device_id", http.StatusNotFound)
		return
	}
	if err != nil {
		h.fail(w, "devices: get", err)
		return
	}
	d.Connected = h.live.Connected(d.DeviceID)
	writeJSON(w, http.StatusOK, d)
}

func (h *Handler) summary(w http.ResponseWriter, r *http.Request) {
	th, err := h.thresholds(r.Context())
	if err != nil {
		h.fail(w, "devices: thresholds", err)
		return
	}
	rows, err := h.pool.Query(r.Context(), `SELECT `+stateSQL+` AS state, count(*), count(*) FILTER (WHERE `+staleAlertSQL+`)
		FROM devices d GROUP BY 1`, th.onlineSince, th.staleBefore)
	if err != nil {
		h.fail(w, "devices: summary", err)
		return
	}
	defer rows.Close()
	counts := map[string]int{}
	for _, s := range States {
		counts[s] = 0
	}
	total, staleAlert := 0, 0
	for rows.Next() {
		var s string
		var n, alert int
		if err := rows.Scan(&s, &n, &alert); err != nil {
			h.fail(w, "devices: summary", err)
			return
		}
		counts[s] = n
		total += n
		staleAlert += alert
	}
	if err := rows.Err(); err != nil {
		h.fail(w, "devices: summary", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "states": counts, "stale_alert": staleAlert,
		"online_since": th.onlineSince.UTC(), "stale_before": th.staleBefore.UTC()})
}

// RetireRequest is the POST body.
type RetireRequest struct {
	DeviceIDs []string `json:"device_ids"`
	Reason    string   `json:"reason"`
}

// Retired is the outcome for one device: retired, already_retired or unknown_device.
type Retired struct {
	DeviceID       string `json:"device_id"`
	Status         string `json:"status"`
	AgentsRevoked  int64  `json:"agents_revoked,omitempty"`
	CertsRevoked   int64  `json:"certificates_revoked,omitempty"`
	CommandsFailed int64  `json:"commands_failed,omitempty"`
	Disconnected   bool   `json:"disconnected,omitempty"`
}

func validateRetire(req *RetireRequest) error {
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		return errors.New("reason is required")
	}
	if len([]rune(req.Reason)) > MaxReason {
		return fmt.Errorf("reason: at most %d characters", MaxReason)
	}
	for _, c := range req.Reason {
		if unicode.IsControl(c) {
			return errors.New("reason: no control characters")
		}
	}
	req.DeviceIDs = dedupe(req.DeviceIDs)
	if len(req.DeviceIDs) == 0 || len(req.DeviceIDs) > MaxRetire {
		return fmt.Errorf("device_ids: 1..%d devices", MaxRetire)
	}
	return nil
}

func (h *Handler) retire(w http.ResponseWriter, r *http.Request, caller apiauth.Principal) {
	var req RetireRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateRetire(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	actor := "api_client:" + caller.ClientName
	results := make([]Retired, 0, len(req.DeviceIDs))
	counts := map[string]int{}
	for _, dev := range req.DeviceIDs {
		res, err := h.retireOne(r.Context(), dev, req.Reason, actor, caller.ClientID)
		if err != nil {
			h.log.Error("device retire failed", "device_id", dev, "error", err.Error())
			http.Error(w, "could not retire device "+dev+"; devices before it in the list were retired", http.StatusInternalServerError)
			return
		}
		// Only after the revocation is committed: the agent's reconnect is then refused.
		if res.Status == "retired" {
			res.Disconnected = h.live.Disconnect(dev)
		}
		counts[res.Status]++
		results = append(results, res)
	}
	h.log.Info("devices retired", "requested", len(req.DeviceIDs), "retired", counts["retired"],
		"already_retired", counts["already_retired"], "unknown", counts["unknown_device"], "client", caller.ClientName)
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "counts": counts})
}

// retireOne does one device in one transaction.
func (h *Handler) retireOne(ctx context.Context, deviceID, reason, actor, clientID string) (Retired, error) {
	res := Retired{DeviceID: deviceID}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	var uuid, hostname, status string
	err = tx.QueryRow(ctx, `SELECT id, hostname, status FROM devices WHERE agent_reported_id = $1 FOR UPDATE`, deviceID).
		Scan(&uuid, &hostname, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		res.Status = "unknown_device"
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("lock device: %w", err)
	}
	if status == "decommissioned" {
		res.Status = "already_retired"
		return res, nil
	}

	if _, err := tx.Exec(ctx, `
		UPDATE devices SET status = 'decommissioned', retired_at = now(), retired_reason = $2, retired_by = $3
		WHERE id = $1`, uuid, reason, actor); err != nil {
		return res, fmt.Errorf("retire device: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE agent_certificates SET revoked_at = now(), revoked_reason = 'device retired'
		WHERE revoked_at IS NULL AND agent_id IN (SELECT id FROM agents WHERE device_id = $1)`, uuid)
	if err != nil {
		return res, fmt.Errorf("revoke certificates: %w", err)
	}
	res.CertsRevoked = tag.RowsAffected()
	tag, err = tx.Exec(ctx, `
		UPDATE agents SET revoked_at = now(), revoked_reason = 'device retired: ' || $2
		WHERE device_id = $1 AND revoked_at IS NULL`, uuid, reason)
	if err != nil {
		return res, fmt.Errorf("revoke agents: %w", err)
	}
	res.AgentsRevoked = tag.RowsAffected()
	// Jobs waiting on these commands (deployments, transfers) see them fail and move on.
	tag, err = tx.Exec(ctx, `
		UPDATE agent_commands SET status = 'failed', completed_at = now(), result = '{"error": "device retired"}'::jsonb
		WHERE status IN ('queued', 'dispatched', 'acknowledged') AND agent_id IN (SELECT id FROM agents WHERE device_id = $1)`, uuid)
	if err != nil {
		return res, fmt.Errorf("fail open commands: %w", err)
	}
	res.CommandsFailed = tag.RowsAffected()

	details, _ := json.Marshal(map[string]any{
		"device_id": deviceID, "hostname": hostname, "reason": reason, "previous_status": status,
		"agents_revoked": res.AgentsRevoked, "certificates_revoked": res.CertsRevoked, "commands_failed": res.CommandsFailed,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', $1, $2, 'device.retire', 'device', $3, $4::jsonb)`,
		clientID, actor, uuid, string(details)); err != nil {
		return res, fmt.Errorf("insert audit_log: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return res, err
	}
	res.Status = "retired"
	return res, nil
}

func (h *Handler) fail(w http.ResponseWriter, what string, err error) {
	h.log.Error(what, "error", err.Error())
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func dedupe(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck // client went away
}
