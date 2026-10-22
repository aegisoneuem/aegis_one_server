package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const pass = "correct horse battery staple"

func newTestCA(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	enc, err := EncryptKey(key, pass)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "ca.key.enc"), enc, 0o600)
	return dir
}

func csrPEM(t *testing.T, cn string) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestEncryptedKeyRoundTripAndFailures(t *testing.T) {
	dir := newTestCA(t)
	if _, err := Load(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key.enc"), pass); err != nil {
		t.Fatalf("load with right passphrase: %v", err)
	}
	if _, err := Load(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key.enc"), pass+"x"); err == nil {
		t.Fatal("loaded with the wrong passphrase")
	}
	// Flip one ciphertext byte: GCM must reject it.
	enc, _ := os.ReadFile(filepath.Join(dir, "ca.key.enc"))
	tampered := []byte(string(enc))
	i := len(tampered) - 10
	tampered[i] ^= 0x01
	if _, err := DecryptKey(tampered, pass); err == nil {
		t.Fatal("decrypted a tampered key file")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := EncryptKey(key, "short"); err == nil {
		t.Fatal("accepted a too-short passphrase")
	}
}

func TestKeyMustMatchCert(t *testing.T) {
	dir := newTestCA(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc, _ := EncryptKey(other, pass)
	os.WriteFile(filepath.Join(dir, "ca.key.enc"), enc, 0o600)
	if _, err := Load(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key.enc"), pass); err == nil {
		t.Fatal("accepted a key that doesn't match the CA cert")
	}
}

func TestSignClientUsesServerChosenCN(t *testing.T) {
	dir := newTestCA(t)
	c, err := Load(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key.enc"), pass)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSR(csrPEM(t, "whatever-the-agent-asked-for"))
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := c.SignClient(csr, "assigned-device-id", 398*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "assigned-device-id" {
		t.Fatalf("CN = %q, want the server-assigned id", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("EKU = %v, want ClientAuth only", cert.ExtKeyUsage)
	}
	if cert.NotAfter.After(c.Cert.NotAfter) {
		t.Fatal("client cert outlives the CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("issued cert doesn't chain to the CA: %v", err)
	}
}

func TestParseCSRRejects(t *testing.T) {
	if _, err := ParseCSR("not a csr"); err == nil {
		t.Fatal("accepted garbage")
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, weak)
	if _, err := ParseCSR(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))); err == nil {
		t.Fatal("accepted a 1024-bit RSA key")
	}
	// Tamper with a valid CSR's signature.
	good := csrPEM(t, "x")
	block, _ := pem.Decode([]byte(good))
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	if _, err := ParseCSR(string(pem.EncodeToMemory(block))); err == nil {
		t.Fatal("accepted a CSR with a broken signature")
	}
}
