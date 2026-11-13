// Package enroll implements the agent's Enroll and Renew RPCs (agent team's
// server-team-handoff.md and server-identity-reconciliation-contract.md).
//
// Enroll: token-authenticated, no client cert yet. Validates the per-tenant
// enrollment token, reconciles the request to ONE logical device by hardware
// signals (strongest first), enforces the device-seat cap, signs the agent's
// CSR with the enrollment CA (CN = the reconciled device_id), and returns the
// cert + assigned_device_id + computer_id. Business rejections go in
// EnrollResponse.error (the agent fails loud on it); everything happens in one
// transaction so a crash can't half-register a device.
//
// Reconciling only decides which device RECORD the agent belongs to (agent
// track's TPM device identity spec); it never authorizes anything. Only a
// strong signal (TPM EK, the agent's own device_id) reactivates an existing
// record automatically. A weak one (SMBIOS UUID, MachineGuid), or a strong one
// whose record has an agent connected right now, gets a new record plus a
// device_merge_candidates row for an admin (see 0023). Hostname is never used.
//
// Renew: called over an existing mTLS connection (no token); signs a fresh cert
// for the already-authenticated device.
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/ca"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool       *pgxpool.Pool
	ca         *ca.CA
	certTTL    time.Duration
	licenseMax int // 0 = unlimited
	live       Live
	log        *slog.Logger
}

// Live says whether a device's agent has a live stream right now.
type Live interface {
	Connected(deviceID string) bool
}

// SetLive enables the "agent connected right now" conflict check. Without it a
// strong match always reactivates.
func (s *Service) SetLive(l Live) { s.live = l }

func New(pool *pgxpool.Pool, authority *ca.CA, certTTL time.Duration, licenseMax int, log *slog.Logger) *Service {
	return &Service{pool: pool, ca: authority, certTTL: certTTL, licenseMax: licenseMax, log: log}
}

// HashToken is how enrollment tokens are stored (enrollment_tokens.token_hash):
// tokens are 256-bit random, so a fast hash is appropriate.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// rejection is a business refusal the agent should see verbatim.
type rejection string

func (r rejection) Error() string { return string(r) }

const errBadToken = rejection("enrollment token is invalid, expired, revoked or used up")

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type signals struct {
	deviceID, tpmEK, systemUUID, machineGUID string
}

func normalize(req *aegisonev1.EnrollRequest) signals {
	s := signals{
		tpmEK:       strings.TrimSpace(req.GetTpmEk()),
		systemUUID:  strings.ToLower(strings.TrimSpace(req.GetSystemUuid())),
		machineGUID: strings.ToLower(strings.TrimSpace(req.GetMachineGuid())),
	}
	if id := strings.ToLower(strings.TrimSpace(req.GetDeviceId())); uuidRe.MatchString(id) {
		s.deviceID = id
	}
	// Some VMs / OEM batches report an all-zero or all-F SMBIOS UUID; that
	// identifies nothing and must never merge two machines.
	if strings.Trim(s.systemUUID, "0-") == "" || strings.Trim(s.systemUUID, "f-") == "" {
		s.systemUUID = ""
	}
	return s
}

// Enroll never returns a Go error for business outcomes; those are in
// resp.Error. Unexpected failures are logged and reported generically.
func (s *Service) Enroll(ctx context.Context, req *aegisonev1.EnrollRequest, remote string) *aegisonev1.EnrollResponse {
	resp, err := s.enroll(ctx, req)
	if err == nil {
		return resp
	}
	var rej rejection
	if errors.As(err, &rej) {
		s.log.Warn("enrollment rejected", "reason", string(rej), "hostname", req.GetHostname(), "remote", remote)
		return &aegisonev1.EnrollResponse{Error: string(rej)}
	}
	s.log.Error("enrollment failed", "error", err.Error(), "hostname", req.GetHostname(), "remote", remote)
	return &aegisonev1.EnrollResponse{Error: "enrollment failed on the server; retry later"}
}

func (s *Service) enroll(ctx context.Context, req *aegisonev1.EnrollRequest) (*aegisonev1.EnrollResponse, error) {
	if strings.TrimSpace(req.GetEnrollToken()) == "" {
		return nil, errBadToken
	}
	csr, err := ca.ParseCSR(req.GetCsrPem())
	if err != nil {
		return nil, rejection("invalid CSR: " + err.Error())
	}
	sig := normalize(req)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	// Serialize enrollments: seat counting and "is this device already known"
	// must not race between two agents enrolling at the same moment.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('aegis-enroll'))`); err != nil {
		return nil, err
	}

	tokenID, err := checkToken(ctx, tx, req.GetEnrollToken())
	if err != nil {
		return nil, err
	}

	m, err := reconcile(ctx, tx, sig)
	if err != nil {
		return nil, err
	}
	m, review := classify(m, s.live)
	var dev *device
	matchedBy := ""
	if m != nil {
		dev, matchedBy = &m.dev, m.by
	}
	reconciled := dev != nil

	// A seat is consumed by a new device, or by a decommissioned one coming
	// back; re-enrolling an active device (reinstall, dedup) costs nothing.
	if !reconciled || dev.status != "active" {
		if err := s.checkSeat(ctx, tx); err != nil {
			return nil, err
		}
	}

	var commandsFailed int64
	if reconciled {
		if dev.computerID == 0 { // e.g. a device first seen before enrollment existed
			if dev.computerID, err = allocateComputerID(ctx, tx); err != nil {
				return nil, err
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE devices SET
				tpm_ek      = COALESCE(tpm_ek, NULLIF($2, '')),   -- never flip an existing EK
				smbios_uuid = COALESCE(NULLIF($3, ''), smbios_uuid),
				machine_id  = COALESCE(NULLIF($4, ''), machine_id),
				hostname    = COALESCE(NULLIF($5, ''), hostname),
				computer_id = $6, status = 'active', last_seen_at = now(),
				retired_at = NULL, retired_reason = NULL, retired_by = NULL   -- re-enrolling brings a retired device back
			WHERE id = $1`,
			dev.id, sig.tpmEK, sig.systemUUID, sig.machineGUID, req.GetHostname(), dev.computerID); err != nil {
			return nil, fmt.Errorf("update device: %w", err)
		}
		// Commands issued to the record before this enrollment must not reach the
		// returning agent (secure parameters, transfers, reboots); their jobs see
		// them fail and move on, as with retire.
		tag, err := tx.Exec(ctx, `
			UPDATE agent_commands SET status = 'failed', completed_at = now(), result = '{"error": "device re-enrolled"}'::jsonb
			WHERE status IN ('queued', 'dispatched', 'acknowledged') AND agent_id IN (SELECT id FROM agents WHERE device_id = $1)`, dev.id)
		if err != nil {
			return nil, fmt.Errorf("fail open commands: %w", err)
		}
		commandsFailed = tag.RowsAffected()
		if h := strings.TrimSpace(req.GetHostname()); h != "" && h != dev.hostname {
			if err := audit(ctx, tx, "device.rename", dev.deviceID, dev.id, Renamed(dev.hostname, h)); err != nil {
				return nil, err
			}
		}
	} else {
		dev = &device{status: "active"}
		dev.deviceID = sig.deviceID
		if dev.deviceID == "" || idTaken(ctx, tx, dev.deviceID) {
			if dev.deviceID, err = newUUID(); err != nil {
				return nil, err
			}
		}
		if dev.computerID, err = allocateComputerID(ctx, tx); err != nil {
			return nil, err
		}
		// The EK is unique per record; in a conflict it stays with the existing one.
		tpm := sig.tpmEK
		if review != nil && review.by == "tpm_ek_conflict" {
			tpm = ""
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO devices (hostname, os_family, agent_reported_id, tpm_ek, smbios_uuid, machine_id, computer_id, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), $7, now(), now())
			RETURNING id`,
			firstNonEmpty(req.GetHostname(), dev.deviceID), osFamily(req.GetOs()), dev.deviceID,
			tpm, sig.systemUUID, sig.machineGUID, dev.computerID).Scan(&dev.id); err != nil {
			return nil, fmt.Errorf("create device: %w", err)
		}
		if review != nil {
			if _, err := tx.Exec(ctx, `
				INSERT INTO device_merge_candidates (new_device_id, existing_device_id, matched_by, matched_value)
				VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
				dev.id, review.dev.id, review.by, review.value); err != nil {
				return nil, fmt.Errorf("record merge candidate: %w", err)
			}
			if err := audit(ctx, tx, "device.duplicate_flagged", dev.deviceID, dev.id, map[string]any{
				"message":            "Possible duplicate - reconcile?",
				"new_device_id":      dev.deviceID,
				"existing_device_id": review.dev.deviceID,
				"matched_by":         review.by,
				"existing_state":     review.dev.state,
			}); err != nil {
				return nil, err
			}
		}
	}

	agentID, err := upsertAgent(ctx, tx, dev.id, req.GetAgentVersion(), tokenID)
	if err != nil {
		return nil, err
	}

	cert, certPEM, err := s.ca.SignClient(csr, dev.deviceID, s.certTTL)
	if err != nil {
		return nil, fmt.Errorf("sign client cert: %w", err)
	}
	if err := recordCert(ctx, tx, agentID, cert); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE id = $1`, tokenID); err != nil {
		return nil, err
	}

	if err := audit(ctx, tx, "agent.enroll", dev.deviceID, dev.id, map[string]any{
		"reconciled": reconciled, "matched_by": matchedBy, "computer_id": dev.computerID,
		"hostname": req.GetHostname(), "requested_device_id": req.GetDeviceId(), "enrollment_token_id": tokenID,
		"cert_not_after": cert.NotAfter,
	}); err != nil {
		return nil, err
	}
	if reconciled {
		if err := audit(ctx, tx, "device.reactivate", dev.deviceID, dev.id, map[string]any{
			"message":             fmt.Sprintf("Device reactivated via %s match - previous status: %s", matchLabel(matchedBy), dev.state),
			"matched_by":          matchedBy,
			"previous_status":     dev.state,
			"requested_device_id": req.GetDeviceId(),
			"device_id":           dev.deviceID,
			"commands_failed":     commandsFailed,
		}); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.log.Info("agent enrolled", "device_id", dev.deviceID, "computer_id", dev.computerID,
		"reconciled", reconciled, "matched_by", matchedBy, "hostname", req.GetHostname())
	if review != nil {
		s.log.Warn("enrollment flagged as possible duplicate", "device_id", dev.deviceID,
			"existing_device_id", review.dev.deviceID, "matched_by", review.by)
	}

	return &aegisonev1.EnrollResponse{
		ClientCertPem:    string(certPEM),
		CaChainPem:       string(s.ca.CertPEM),
		AssignedDeviceId: dev.deviceID,
		ComputerId:       strconv.FormatInt(dev.computerID, 10),
	}, nil
}

func checkToken(ctx context.Context, tx pgx.Tx, raw string) (string, error) {
	var id string
	var maxUses, useCount int
	var expires time.Time
	var revoked *time.Time
	err := tx.QueryRow(ctx, `
		SELECT id, max_uses, use_count, expires_at, revoked_at
		FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE`, HashToken(strings.TrimSpace(raw)),
	).Scan(&id, &maxUses, &useCount, &expires, &revoked)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", errBadToken
	case err != nil:
		return "", err
	case revoked != nil, time.Now().After(expires), useCount >= maxUses:
		return "", errBadToken
	}
	return id, nil
}

type device struct {
	id, deviceID, status, hostname string
	state                          string // online/offline/stale/retired/unmanaged when matched
	computerID                     int64
}

// match is the existing record an enrollment's signals point at.
type match struct {
	dev    device
	by     string // tpm_ek, device_id, system_uuid, machine_guid
	value  string
	strong bool // tpm_ek / device_id: may reactivate without review
}

// matchSQL reads a candidate record with its lifecycle state (same rules as
// internal/devices). Records merged into another are skipped.
const matchSQL = `
	SELECT id, coalesce(agent_reported_id, ''), status, coalesce(computer_id, 0), hostname,
	       CASE WHEN status = 'decommissioned' THEN 'retired'
	            WHEN status = 'unmanaged' THEN 'unmanaged'
	            WHEN last_seen_at >= now() - make_interval(mins => setting_int('agent.offline_after_minutes', 15)) THEN 'online'
	            WHEN last_seen_at >= now() - make_interval(days => setting_int('device.stale_after_days', 30)) THEN 'offline'
	            ELSE 'stale' END
	FROM devices WHERE merged_into_device_id IS NULL AND `

// reconcile finds the existing device for these signals, strongest first:
// tpm_ek (unique, clone-proof) > device_id > smbios uuid > machine guid. The two
// weak signals only count if they match exactly ONE device - some hardware
// batches share them - and even then only as a review candidate.
func reconcile(ctx context.Context, tx pgx.Tx, s signals) (*match, error) {
	try := []struct {
		name, value, where string
		strong             bool
	}{
		{"tpm_ek", s.tpmEK, "tpm_ek = $1", true},
		{"device_id", s.deviceID, "agent_reported_id = $1", true},
		{"system_uuid", s.systemUUID, "lower(smbios_uuid) = $1", false},
		{"machine_guid", s.machineGUID, "lower(machine_id) = $1", false},
	}
	for _, t := range try {
		if t.value == "" {
			continue
		}
		rows, err := tx.Query(ctx, matchSQL+t.where+` LIMIT 2`, t.value)
		if err != nil {
			return nil, err
		}
		var found []device
		for rows.Next() {
			var d device
			if err := rows.Scan(&d.id, &d.deviceID, &d.status, &d.computerID, &d.hostname, &d.state); err != nil {
				rows.Close()
				return nil, err
			}
			found = append(found, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(found) == 1 || (len(found) > 1 && t.strong) {
			d := found[0]
			if d.deviceID == "" { // legacy row without an agent-facing id
				id, err := newUUID()
				if err != nil {
					return nil, err
				}
				if _, err := tx.Exec(ctx, `UPDATE devices SET agent_reported_id = $2 WHERE id = $1`, d.id, id); err != nil {
					return nil, err
				}
				d.deviceID = id
			}
			return &match{dev: d, by: t.name, value: t.value, strong: t.strong}, nil
		}
	}
	return nil, nil
}

// classify splits a match into what enrollment acts on now (a strong match:
// reactivate that record) and what an admin must review (a weak match, or a
// strong one whose record has an agent connected right now - a cloned VM, or
// someone else's identity). At most one of the two is set.
func classify(m *match, live Live) (act, review *match) {
	if m == nil {
		return nil, nil
	}
	if m.strong && (live == nil || !live.Connected(m.dev.deviceID)) {
		return m, nil
	}
	r := *m
	if r.strong {
		r.by += "_conflict"
	}
	return nil, &r
}

func matchLabel(by string) string {
	switch by {
	case "tpm_ek":
		return "TPM"
	case "device_id":
		return "agent device_id"
	}
	return by
}

// Renamed is the audit detail for a hostname change. Hostname is an attribute,
// not an identity signal, but admins want to see renames.
func Renamed(from, to string) map[string]any {
	return map[string]any{"message": fmt.Sprintf("Device renamed from %s to %s", from, to), "from": from, "to": to}
}

func audit(ctx context.Context, tx pgx.Tx, action, deviceID, deviceUUID string, details map[string]any) error {
	b, _ := json.Marshal(details)
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_label, action, target_type, target_id, details)
		VALUES ('agent', $1, $2, 'device', $3, $4::jsonb)`, deviceID, action, deviceUUID, string(b)); err != nil {
		return fmt.Errorf("audit_log %s: %w", action, err)
	}
	return nil
}

func (s *Service) checkSeat(ctx context.Context, tx pgx.Tx) error {
	if s.licenseMax == 0 {
		return nil
	}
	var used int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE status = 'active' AND management_type = 'agent'`).Scan(&used); err != nil {
		return err
	}
	if used >= s.licenseMax {
		return rejection(fmt.Sprintf("license limit reached (%d devices)", s.licenseMax))
	}
	return nil
}

// allocateComputerID picks a random unused id in [1000000000, 9999999999].
// Called under the enrollment lock, so check-then-insert can't race.
func allocateComputerID(ctx context.Context, tx pgx.Tx) (int64, error) {
	for range 20 {
		n, err := rand.Int(rand.Reader, big.NewInt(9_000_000_000))
		if err != nil {
			return 0, err
		}
		id := n.Int64() + 1_000_000_000
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE computer_id = $1)`, id).Scan(&taken); err != nil {
			return 0, err
		}
		if !taken {
			return id, nil
		}
	}
	return 0, errors.New("could not allocate a unique computer_id")
}

func idTaken(ctx context.Context, tx pgx.Tx, deviceID string) bool {
	var taken bool
	tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE agent_reported_id = $1)`, deviceID).Scan(&taken)
	return taken
}

// upsertAgent keeps one live agent per device. Re-enrollment means the agent
// generated a NEW key pair, so every earlier certificate of that agent is
// revoked - the old private key should no longer exist anywhere.
func upsertAgent(ctx context.Context, tx pgx.Tx, deviceUUID, agentVersion, tokenID string) (string, error) {
	var agentID string
	err := tx.QueryRow(ctx, `SELECT id FROM agents WHERE device_id = $1 AND revoked_at IS NULL`, deviceUUID).Scan(&agentID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		err = tx.QueryRow(ctx, `
			INSERT INTO agents (device_id, agent_version, install_method, enrollment_token_id)
			VALUES ($1, $2, 'unknown', $3) RETURNING id`,
			deviceUUID, firstNonEmpty(agentVersion, "unknown"), tokenID).Scan(&agentID)
		if err != nil {
			return "", fmt.Errorf("create agent: %w", err)
		}
		return agentID, nil
	case err != nil:
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agents SET agent_version = COALESCE(NULLIF($2, ''), agent_version), enrollment_token_id = $3
		WHERE id = $1`, agentID, agentVersion, tokenID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_certificates SET revoked_at = now(), revoked_reason = 're-enrolled'
		WHERE agent_id = $1 AND revoked_at IS NULL`, agentID); err != nil {
		return "", fmt.Errorf("revoke previous certs: %w", err)
	}
	return agentID, nil
}

func recordCert(ctx context.Context, tx pgx.Tx, agentID string, cert *x509.Certificate) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO agent_certificates (agent_id, serial_number, fingerprint_sha256, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5)`,
		agentID, cert.SerialNumber.String(), identity.Fingerprint(cert), cert.NotBefore, cert.NotAfter)
	if err != nil {
		return fmt.Errorf("record certificate: %w", err)
	}
	return nil
}

// Renew signs a new client certificate for an already-authenticated device.
// The device id comes from the caller's verified identity, never from the CSR.
// The previous cert is left valid until it expires: revoking it now would
// strand an agent that fails to persist the new one.
func (s *Service) Renew(ctx context.Context, known *identity.Known, req *aegisonev1.RenewRequest) *aegisonev1.RenewResponse {
	csr, err := ca.ParseCSR(req.GetCsrPem())
	if err != nil {
		return &aegisonev1.RenewResponse{Error: "invalid CSR: " + err.Error()}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.log.Error("renew failed", "device_id", known.DeviceID, "error", err.Error())
		return &aegisonev1.RenewResponse{Error: "renewal failed on the server; retry later"}
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	cert, certPEM, err := s.ca.SignClient(csr, known.DeviceID, s.certTTL)
	if err == nil {
		err = recordCert(ctx, tx, known.AgentUUID, cert)
	}
	if err == nil {
		details, _ := json.Marshal(map[string]any{"cert_not_after": cert.NotAfter})
		_, err = tx.Exec(ctx, `
			INSERT INTO audit_log (actor_type, actor_label, action, target_type, target_id, details)
			VALUES ('agent', $1, 'agent.cert.renew', 'device', $2, $3::jsonb)`, known.DeviceID, known.DeviceUUID, string(details))
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		s.log.Error("renew failed", "device_id", known.DeviceID, "error", err.Error())
		return &aegisonev1.RenewResponse{Error: "renewal failed on the server; retry later"}
	}
	s.log.Info("agent certificate renewed", "device_id", known.DeviceID, "not_after", cert.NotAfter)
	return &aegisonev1.RenewResponse{ClientCertPem: string(certPEM)}
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func firstNonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func osFamily(os string) string {
	switch strings.ToLower(strings.TrimSpace(os)) {
	case "linux":
		return "linux"
	case "macos", "darwin":
		return "macos"
	default:
		return "windows"
	}
}
