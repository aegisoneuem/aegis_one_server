// Package ca is the server's enrollment certificate authority: it signs each
// agent's CSR into a client certificate (CN = the device's assigned device_id).
//
// The CA private key never sits on disk in plaintext. It is stored as JSON
// {format, kdf, iterations, salt, nonce, ciphertext}: PKCS#8 DER sealed with
// AES-256-GCM under a key derived from a passphrase with PBKDF2-SHA256. The
// passphrase reaches the server via env/secret file (Sam's choice for v1 - a real
// secrets store / HSM is still an open item in CLAUDE.md).
package ca

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	keyFormat = "aegis-ca-key-v1"
	// OWASP's 2023 minimum for PBKDF2-HMAC-SHA256. Costs a fraction of a second,
	// once, at server start.
	kdfIterations = 600_000
	// MinPassphraseLen guards against trivially guessable passphrases when a key
	// is (re)encrypted.
	MinPassphraseLen = 16
)

type encryptedKey struct {
	Format     string `json:"format"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// EncryptKey seals key for storage on disk.
func EncryptKey(key crypto.Signer, passphrase string) ([]byte, error) {
	if len(passphrase) < MinPassphraseLen {
		return nil, fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLen)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	gcm, err := newGCM(passphrase, salt, kdfIterations)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return json.MarshalIndent(encryptedKey{
		Format: keyFormat, KDF: "pbkdf2-sha256", Iterations: kdfIterations,
		Salt: salt, Nonce: nonce,
		Ciphertext: gcm.Seal(nil, nonce, der, []byte(keyFormat)), // format bound as AAD
	}, "", "  ")
}

// DecryptKey opens a key written by EncryptKey. A wrong passphrase and a
// tampered file both fail authentication.
func DecryptKey(data []byte, passphrase string) (crypto.Signer, error) {
	var ek encryptedKey
	if err := json.Unmarshal(data, &ek); err != nil {
		return nil, fmt.Errorf("parse encrypted key: %w", err)
	}
	if ek.Format != keyFormat || ek.KDF != "pbkdf2-sha256" || ek.Iterations < 100_000 {
		return nil, fmt.Errorf("unsupported encrypted key (format %q, kdf %q, iterations %d)", ek.Format, ek.KDF, ek.Iterations)
	}
	gcm, err := newGCM(passphrase, ek.Salt, ek.Iterations)
	if err != nil {
		return nil, err
	}
	der, err := gcm.Open(nil, ek.Nonce, ek.Ciphertext, []byte(keyFormat))
	if err != nil {
		return nil, errors.New("cannot decrypt CA key: wrong passphrase or corrupted file")
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key is not a signing key")
	}
	return signer, nil
}

func newGCM(passphrase string, salt []byte, iterations int) (cipher.AEAD, error) {
	k, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer
}

// Load reads the CA certificate and its encrypted key, and checks they belong
// together.
func Load(certPath, encKeyPath, passphrase string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA cert %q is not a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%q is not a CA certificate", certPath)
	}
	enc, err := os.ReadFile(encKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	key, err := DecryptKey(enc, passphrase)
	if err != nil {
		return nil, err
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("CA key does not match the CA certificate")
	}
	return &CA{Cert: cert, CertPEM: pem.EncodeToMemory(block), key: key}, nil
}

// ParseCSR decodes and checks an agent CSR: valid PEM, self-signature verifies
// (proves possession of the private key), and an acceptable key type.
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr_pem is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, errors.New("CSR key must be ECDSA P-256/P-384 or RSA >= 2048")
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("CSR RSA key shorter than 2048 bits")
		}
	default:
		return nil, errors.New("CSR key must be ECDSA P-256/P-384 or RSA >= 2048")
	}
	return csr, nil
}

// SignClient issues an agent client certificate for csr's key. The subject is
// set by the server (CN = deviceID, the RECONCILED id) - whatever the CSR
// asked for is ignored.
func (c *CA) SignClient(csr *x509.CertificateRequest, deviceID string, ttl time.Duration) (*x509.Certificate, []byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	notAfter := now.Add(ttl)
	if notAfter.After(c.Cert.NotAfter) {
		notAfter = c.Cert.NotAfter // never outlive the CA
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID, Organization: []string{"Aegis One"}},
		NotBefore:    now.Add(-5 * time.Minute), // tolerate small endpoint clock skew
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
