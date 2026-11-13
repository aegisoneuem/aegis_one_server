package devices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"aegis-one/internal/apiauth"

	"github.com/jackc/pgx/v5"
)

// Possible duplicates come from enrollment (internal/enroll, 0023): a weak
// hardware match (SMBIOS UUID, MachineGuid), or a strong one (TPM EK,
// device_id) whose record had an agent connected at that moment. Nothing is
// merged until an admin confirms.
//
// Confirming moves the new record's agent onto the existing record, which keeps
// its history, computer_id and audit trail; the new record becomes "merged".
// The existing record takes over the agent's device_id (it is the CN of the
// agent's certificate). Data the agent reported under the new record stays
// there; the agent is disconnected so it reconnects as the existing record and
// reports again.

// MaxDuplicates caps one duplicates page.
const MaxDuplicates = 500

var candidateStatuses = map[string]bool{"pending": true, "confirmed": true, "rejected": true}

// DuplicateSide is one of the two records of a candidate.
type DuplicateSide struct {
	DeviceID    string     `json:"device_id"`
	Hostname    string     `json:"hostname"`
	State       string     `json:"state"`
	Connected   bool       `json:"connected"`
	ComputerID  *int64     `json:"computer_id,omitempty"`
	OSBuild     *string    `json:"os_build,omitempty"`
	SerialHint  *string    `json:"smbios_uuid,omitempty"`
	FirstSeenAt time.Time  `json:"first_seen_at"`
	LastSeenAt  *time.Time `json:"last_seen_at"`
}

// Duplicate is one device_merge_candidates row.
type Duplicate struct {
	ID        string        `json:"id"`
	MatchedBy string        `json:"matched_by"`
	Status    string        `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	DecidedAt *time.Time    `json:"decided_at,omitempty"`
	DecidedBy *string       `json:"decided_by,omitempty"`
	Reason    *string       `json:"decision_reason,omitempty"`
	New       DuplicateSide `json:"new_device"`
	Existing  DuplicateSide `json:"existing_device"`
}

const sideSQL = `coalesce(%[1]s.agent_reported_id, %[1]s.id::text), %[1]s.hostname,
	CASE WHEN %[1]s.merged_into_device_id IS NOT NULL THEN 'merged'
	     WHEN %[1]s.status = 'decommissioned' THEN 'retired'
	     WHEN %[1]s.status = 'unmanaged' THEN 'unmanaged'
	     WHEN %[1]s.last_seen_at >= $1 THEN 'online'
	     WHEN %[1]s.last_seen_at >= $2 THEN 'offline'
	     ELSE 'stale' END,
	%[1]s.computer_id, CASE WHEN %[1]s.os_build IS NULL THEN NULL WHEN %[1]s.os_ubr IS NULL THEN %[1]s.os_build ELSE %[1]s.os_build || '.' || %[1]s.os_ubr END,
	%[1]s.smbios_uuid, %[1]s.first_seen_at, %[1]s.last_seen_at`

func (h *Handler) duplicates(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	status := strings.ToLower(strings.TrimSpace(qs.Get("status")))
	if status == "" {
		status = "pending"
	}
	if status != "all" && !candidateStatuses[status] {
		http.Error(w, "status must be one of pending, confirmed, rejected or all", http.StatusUnprocessableEntity)
		return
	}
	limit := DefaultLimit
	if v := qs.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxDuplicates {
			http.Error(w, fmt.Sprintf("limit: 1..%d", MaxDuplicates), http.StatusUnprocessableEntity)
			return
		}
		limit = n
	}
	th, err := h.thresholds(r.Context())
	if err != nil {
		h.fail(w, "duplicates: thresholds", err)
		return
	}
	rows, err := h.pool.Query(r.Context(), `
		SELECT c.id, c.matched_by, c.status, c.created_at, c.decided_at, c.decided_by, c.decision_reason,
		       `+fmt.Sprintf(sideSQL, "n")+`, `+fmt.Sprintf(sideSQL, "e")+`
		FROM device_merge_candidates c
		JOIN devices n ON n.id = c.new_device_id
		JOIN devices e ON e.id = c.existing_device_id
		WHERE ($3 = 'all' OR c.status = $3)
		ORDER BY c.created_at DESC LIMIT $4`, th.onlineSince, th.staleBefore, status, limit)
	if err != nil {
		h.fail(w, "duplicates: list", err)
		return
	}
	defer rows.Close()
	out := make([]Duplicate, 0)
	for rows.Next() {
		var d Duplicate
		n, e := &d.New, &d.Existing
		if err := rows.Scan(&d.ID, &d.MatchedBy, &d.Status, &d.CreatedAt, &d.DecidedAt, &d.DecidedBy, &d.Reason,
			&n.DeviceID, &n.Hostname, &n.State, &n.ComputerID, &n.OSBuild, &n.SerialHint, &n.FirstSeenAt, &n.LastSeenAt,
			&e.DeviceID, &e.Hostname, &e.State, &e.ComputerID, &e.OSBuild, &e.SerialHint, &e.FirstSeenAt, &e.LastSeenAt); err != nil {
			h.fail(w, "duplicates: scan", err)
			return
		}
		n.Connected = h.live.Connected(n.DeviceID)
		e.Connected = h.live.Connected(e.DeviceID)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		h.fail(w, "duplicates: list", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"duplicates": out})
}

// DecideRequest is the confirm / reject body.
type DecideRequest struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// errConflict is a refusal the caller sees with 409.
type errConflict string

func (e errConflict) Error() string { return string(e) }

func (h *Handler) decide(w http.ResponseWriter, r *http.Request, caller apiauth.Principal, confirm bool) {
	var req DecideRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.ID, req.Reason = strings.TrimSpace(req.ID), strings.TrimSpace(req.Reason)
	if !uuidLike(req.ID) {
		http.Error(w, "id: a duplicate id from GET /internal/devices/duplicates", http.StatusUnprocessableEntity)
		return
	}
	if len([]rune(req.Reason)) > MaxReason || strings.IndexFunc(req.Reason, unicode.IsControl) >= 0 {
		http.Error(w, fmt.Sprintf("reason: at most %d characters, no control characters", MaxReason), http.StatusUnprocessableEntity)
		return
	}
	actor := "api_client:" + caller.ClientName
	var res map[string]any
	var err error
	if confirm {
		res, err = h.merge(r.Context(), req, actor, caller.ClientID)
	} else {
		res, err = h.reject(r.Context(), req, actor, caller.ClientID)
	}
	var conflict errConflict
	switch {
	case errors.As(err, &conflict):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, pgx.ErrNoRows):
		http.Error(w, "unknown duplicate id", http.StatusNotFound)
		return
	case err != nil:
		h.fail(w, "duplicates: decide", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type side struct {
	uuid, deviceID, status, hostname string
	mergedInto                       *string
}

// lockCandidate locks a pending candidate and both of its devices (lower
// device uuid first, so two merges can't deadlock).
func lockCandidate(ctx context.Context, tx pgx.Tx, id string) (n, e side, matchedBy string, err error) {
	var status string
	if err = tx.QueryRow(ctx, `
		SELECT new_device_id, existing_device_id, matched_by, status FROM device_merge_candidates WHERE id = $1 FOR UPDATE`, id).
		Scan(&n.uuid, &e.uuid, &matchedBy, &status); err != nil {
		return
	}
	if status != "pending" {
		err = errConflict("duplicate already " + status)
		return
	}
	rows, err := tx.Query(ctx, `
		SELECT id, coalesce(agent_reported_id, ''), status, hostname, merged_into_device_id::text
		FROM devices WHERE id IN ($1, $2) ORDER BY id FOR UPDATE`, n.uuid, e.uuid)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var s side
		if err = rows.Scan(&s.uuid, &s.deviceID, &s.status, &s.hostname, &s.mergedInto); err != nil {
			return
		}
		if s.uuid == n.uuid {
			n = s
		} else {
			e = s
		}
	}
	err = rows.Err()
	return
}

func (h *Handler) merge(ctx context.Context, req DecideRequest, actor, clientID string) (map[string]any, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	n, e, matchedBy, err := lockCandidate(ctx, tx, req.ID)
	if err != nil {
		return nil, err
	}
	switch {
	case n.mergedInto != nil || e.mergedInto != nil:
		return nil, errConflict("one of the two devices was already merged")
	case n.status == "decommissioned":
		return nil, errConflict("the new device is retired; nothing to merge")
	case n.deviceID == "":
		return nil, errConflict("the new device has no agent")
	case e.deviceID != "" && h.live.Connected(e.deviceID):
		return nil, errConflict("the existing device's agent is connected right now - two live agents can't share one record")
	}

	// The existing record's own agents are gone (it was reimaged); revoke them
	// so only the moved agent is live, and fail what was still queued for them.
	certs, err := tx.Exec(ctx, `
		UPDATE agent_certificates SET revoked_at = now(), revoked_reason = 'device merged'
		WHERE revoked_at IS NULL AND agent_id IN (SELECT id FROM agents WHERE device_id = $1)`, e.uuid)
	if err != nil {
		return nil, fmt.Errorf("revoke certificates: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_commands SET status = 'failed', completed_at = now(), result = '{"error": "device merged"}'::jsonb
		WHERE status IN ('queued', 'dispatched', 'acknowledged') AND agent_id IN (SELECT id FROM agents WHERE device_id = $1)`, e.uuid); err != nil {
		return nil, fmt.Errorf("fail open commands: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agents SET revoked_at = now(), revoked_reason = 'device merged: replaced by agent of ' || $2
		WHERE device_id = $1 AND revoked_at IS NULL`, e.uuid, n.deviceID); err != nil {
		return nil, fmt.Errorf("revoke agents: %w", err)
	}
	moved, err := tx.Exec(ctx, `UPDATE agents SET device_id = $2 WHERE device_id = $1`, n.uuid, e.uuid)
	if err != nil {
		return nil, fmt.Errorf("move agent: %w", err)
	}

	// The agent's device_id (its certificate CN) and hardware signals move to the
	// existing record; the TPM EK, unique per record, is freed first.
	var tpm, smbios, machine *string
	if err := tx.QueryRow(ctx, `
		UPDATE devices o SET agent_reported_id = NULL, tpm_ek = NULL, status = 'decommissioned', merged_into_device_id = $2,
			retired_at = now(), retired_reason = 'merged into ' || $3, retired_by = $4
		FROM devices old WHERE o.id = $1 AND old.id = o.id
		RETURNING old.tpm_ek, old.smbios_uuid, old.machine_id`, n.uuid, e.uuid, firstNonEmpty(e.deviceID, e.uuid), actor).
		Scan(&tpm, &smbios, &machine); err != nil {
		return nil, fmt.Errorf("mark new device merged: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET agent_reported_id = $2, tpm_ek = coalesce($3, tpm_ek), smbios_uuid = coalesce($4, smbios_uuid),
			machine_id = coalesce($5, machine_id), hostname = $6, status = 'active',
			last_seen_at = greatest(last_seen_at, (SELECT last_seen_at FROM devices WHERE id = $7)),
			retired_at = NULL, retired_reason = NULL, retired_by = NULL
		WHERE id = $1`, e.uuid, n.deviceID, tpm, smbios, machine, n.hostname, n.uuid); err != nil {
		return nil, fmt.Errorf("update existing device: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE device_merge_candidates SET status = 'confirmed', decided_at = now(), decided_by = $2, decision_reason = NULLIF($3, '')
		WHERE id = $1`, req.ID, actor, req.Reason); err != nil {
		return nil, fmt.Errorf("confirm candidate: %w", err)
	}
	superseded, err := tx.Exec(ctx, `
		UPDATE device_merge_candidates SET status = 'rejected', decided_at = now(), decided_by = $2,
			decision_reason = 'superseded by merge ' || $1
		WHERE status = 'pending' AND id <> $1 AND (new_device_id IN ($3, $4) OR existing_device_id IN ($3, $4))`,
		req.ID, actor, n.uuid, e.uuid)
	if err != nil {
		return nil, fmt.Errorf("supersede candidates: %w", err)
	}

	details := map[string]any{
		"duplicate_id": req.ID, "matched_by": matchedBy, "reason": req.Reason,
		"from_device_id": n.deviceID, "from_device_uuid": n.uuid, "from_hostname": n.hostname,
		"into_device_uuid": e.uuid, "into_previous_device_id": e.deviceID, "into_previous_hostname": e.hostname,
		"into_previous_status": e.status, "device_id_now": n.deviceID,
		"agents_moved": moved.RowsAffected(), "old_certificates_revoked": certs.RowsAffected(),
		"other_candidates_superseded": superseded.RowsAffected(),
	}
	if err := auditAPI(ctx, tx, clientID, actor, "device.merge", e.uuid, details); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	// The agent's open stream still carries the new record's identity; drop it so
	// it reconnects as the existing record.
	disconnected := h.live.Disconnect(n.deviceID)
	h.log.Info("devices merged", "duplicate_id", req.ID, "device_id", n.deviceID, "into", e.uuid,
		"matched_by", matchedBy, "client", actor)
	return map[string]any{"status": "confirmed", "device_id": n.deviceID, "merged_device_uuid": n.uuid,
		"kept_device_uuid": e.uuid, "disconnected": disconnected}, nil
}

func (h *Handler) reject(ctx context.Context, req DecideRequest, actor, clientID string) (map[string]any, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	n, e, matchedBy, err := lockCandidate(ctx, tx, req.ID)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE device_merge_candidates SET status = 'rejected', decided_at = now(), decided_by = $2, decision_reason = NULLIF($3, '')
		WHERE id = $1`, req.ID, actor, req.Reason); err != nil {
		return nil, fmt.Errorf("reject candidate: %w", err)
	}
	if err := auditAPI(ctx, tx, clientID, actor, "device.duplicate_rejected", n.uuid, map[string]any{
		"duplicate_id": req.ID, "matched_by": matchedBy, "reason": req.Reason,
		"new_device_id": n.deviceID, "existing_device_id": firstNonEmpty(e.deviceID, e.uuid),
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"status": "rejected"}, nil
}

func auditAPI(ctx context.Context, tx pgx.Tx, clientID, actor, action, deviceUUID string, details map[string]any) error {
	b, _ := json.Marshal(details)
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', NULLIF($1, '')::uuid, $2, $3, 'device', $4, $5::jsonb)`, clientID, actor, action, deviceUUID, string(b)); err != nil {
		return fmt.Errorf("insert audit_log: %w", err)
	}
	return nil
}

func uuidLike(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}

func firstNonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
