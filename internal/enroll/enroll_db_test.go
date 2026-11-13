package enroll

// Integration test against a throwaway database with all migrations applied:
//
//	AEGIS_TEST_DATABASE_URL=postgres://aegis_server:...@localhost:5433/postgres go test ./internal/enroll/
//
// Skipped when the variable is unset. It creates its own devices and tokens with
// random identifiers and never deletes anything.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/ca"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testService(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	enc, err := ca.EncryptKey(key, "test-passphrase-1234")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "ca.key.enc"), enc, 0o600)
	authority, err := ca.Load(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key.enc"), "test-passphrase-1234")
	if err != nil {
		t.Fatal(err)
	}
	return New(pool, authority, time.Hour, 0, slog.New(slog.NewTextHandler(io.Discard, nil))), pool
}

func rnd() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func token(t *testing.T, pool *pgxpool.Pool) string {
	raw := "tok-" + rnd()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO enrollment_tokens (token_hash, max_uses, expires_at) VALUES ($1, 100, now() + interval '1 hour')`, HashToken(raw)); err != nil {
		t.Fatal(err)
	}
	return raw
}

func csr(t *testing.T) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func newUUIDT(t *testing.T) string {
	id, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEnrollReconcileDB(t *testing.T) {
	svc, pool := testService(t)
	ctx := context.Background()
	tok := token(t, pool)
	tpm, smbios, host := "tpm:"+rnd(), newUUIDT(t), "PC-"+rnd()

	enroll := func(req *aegisonev1.EnrollRequest) *aegisonev1.EnrollResponse {
		t.Helper()
		req.EnrollToken, req.CsrPem, req.Os = tok, csr(t), "windows"
		resp := svc.Enroll(ctx, req, "test")
		if resp.GetError() != "" {
			t.Fatalf("enroll: %s", resp.GetError())
		}
		return resp
	}
	countAudit := func(device, action string) int {
		var n int
		pool.QueryRow(ctx, `SELECT count(*) FROM audit_log a JOIN devices d ON d.id = a.target_id::uuid
			WHERE d.agent_reported_id = $1 AND a.action = $2`, device, action).Scan(&n)
		return n
	}

	// 1. First install.
	first := enroll(&aegisonev1.EnrollRequest{DeviceId: newUUIDT(t), TpmEk: tpm, SystemUuid: smbios, Hostname: host})
	dev := first.GetAssignedDeviceId()

	// 2. Retired, then reimaged (new device_id, new hostname): the TPM brings the
	//    same record back, history kept, rename audited.
	if _, err := pool.Exec(ctx, `UPDATE devices SET status = 'decommissioned', retired_at = now(), retired_reason = 'test' WHERE agent_reported_id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	// A command still queued for the old install must not reach the new one.
	var cmdID string
	if err := pool.QueryRow(ctx, `
		WITH k AS (INSERT INTO signing_keys (key_purpose, public_key, vault_key_ref) VALUES ('command_signing', $2, 'test') RETURNING id)
		INSERT INTO agent_commands (agent_id, command_type, idempotency_key, signature_ed25519, signing_key_id, expires_at)
		SELECT a.id, 'reboot', $2, 'sig', k.id, now() + interval '1 hour'
		FROM agents a JOIN devices d ON d.id = a.device_id, k WHERE d.agent_reported_id = $1 AND a.revoked_at IS NULL
		RETURNING id`, dev, "test-"+rnd()).Scan(&cmdID); err != nil {
		t.Fatal(err)
	}
	again := enroll(&aegisonev1.EnrollRequest{DeviceId: newUUIDT(t), TpmEk: tpm, SystemUuid: smbios, Hostname: host + "-NEW"})
	if again.GetAssignedDeviceId() != dev || again.GetComputerId() != first.GetComputerId() {
		t.Fatalf("TPM match: got %s/%s, want %s/%s", again.GetAssignedDeviceId(), again.GetComputerId(), dev, first.GetComputerId())
	}
	var status, hostname string
	var retiredAt *time.Time
	pool.QueryRow(ctx, `SELECT status, hostname, retired_at FROM devices WHERE agent_reported_id = $1`, dev).Scan(&status, &hostname, &retiredAt)
	if status != "active" || hostname != host+"-NEW" || retiredAt != nil {
		t.Errorf("reactivated device: status=%s hostname=%s retired_at=%v", status, hostname, retiredAt)
	}
	var msg string
	pool.QueryRow(ctx, `SELECT a.details->>'message' FROM audit_log a JOIN devices d ON d.id = a.target_id::uuid
		WHERE d.agent_reported_id = $1 AND a.action = 'device.reactivate'`, dev).Scan(&msg)
	if msg != "Device reactivated via TPM match - previous status: retired" {
		t.Errorf("reactivate audit: %q", msg)
	}
	var cmdStatus string
	pool.QueryRow(ctx, `SELECT status FROM agent_commands WHERE id = $1`, cmdID).Scan(&cmdStatus)
	if cmdStatus != "failed" {
		t.Errorf("queued command after reactivation: %q, want failed", cmdStatus)
	}
	if countAudit(dev, "device.rename") != 1 {
		t.Errorf("rename audits: %d, want 1", countAudit(dev, "device.rename"))
	}

	// 3. Fallback only (no TPM, new device_id, same SMBIOS UUID): never merged,
	//    a new record plus a pending candidate.
	weak := enroll(&aegisonev1.EnrollRequest{DeviceId: newUUIDT(t), SystemUuid: smbios, Hostname: host})
	if weak.GetAssignedDeviceId() == dev {
		t.Fatal("fallback-only match was merged automatically")
	}
	var matchedBy, candStatus string
	if err := pool.QueryRow(ctx, `
		SELECT c.matched_by, c.status FROM device_merge_candidates c
		JOIN devices n ON n.id = c.new_device_id JOIN devices e ON e.id = c.existing_device_id
		WHERE n.agent_reported_id = $1 AND e.agent_reported_id = $2`, weak.GetAssignedDeviceId(), dev).Scan(&matchedBy, &candStatus); err != nil {
		t.Fatalf("no candidate for the fallback match: %v", err)
	}
	if matchedBy != "system_uuid" || candStatus != "pending" {
		t.Errorf("candidate: %s/%s", matchedBy, candStatus)
	}
	if countAudit(weak.GetAssignedDeviceId(), "device.duplicate_flagged") != 1 {
		t.Error("no duplicate_flagged audit")
	}

	// 4. Same TPM while the record's agent is connected (cloned VM): conflict,
	//    new record without the EK, candidate for review.
	svc.SetLive(fakeLive{dev: true})
	clone := enroll(&aegisonev1.EnrollRequest{DeviceId: newUUIDT(t), TpmEk: tpm, Hostname: host + "-CLONE"})
	svc.SetLive(nil)
	if clone.GetAssignedDeviceId() == dev {
		t.Fatal("TPM match on a connected device was reactivated")
	}
	var cloneTPM *string
	pool.QueryRow(ctx, `SELECT tpm_ek FROM devices WHERE agent_reported_id = $1`, clone.GetAssignedDeviceId()).Scan(&cloneTPM)
	if cloneTPM != nil {
		t.Errorf("conflicting record got the EK %q", *cloneTPM)
	}
	pool.QueryRow(ctx, `SELECT c.matched_by FROM device_merge_candidates c JOIN devices n ON n.id = c.new_device_id
		WHERE n.agent_reported_id = $1`, clone.GetAssignedDeviceId()).Scan(&matchedBy)
	if matchedBy != "tpm_ek_conflict" {
		t.Errorf("clone candidate matched_by = %q", matchedBy)
	}

	// 5. Reinstall on the same OS (agent kept its device_id): reactivates, no candidate.
	re := enroll(&aegisonev1.EnrollRequest{DeviceId: weak.GetAssignedDeviceId(), SystemUuid: smbios, Hostname: host})
	if re.GetAssignedDeviceId() != weak.GetAssignedDeviceId() {
		t.Errorf("device_id match: got %s, want %s", re.GetAssignedDeviceId(), weak.GetAssignedDeviceId())
	}
}
