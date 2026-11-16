// Package secretbox seals small server-side secrets (today: per-device agent
// unprotect passcodes) for storage in the database.
//
// The 32-byte master key lives in a key file sealed like the enrollment CA key
// (internal/ca): JSON {format, kdf, iterations, salt, nonce, ciphertext}, the
// key encrypted with AES-256-GCM under a key derived from a passphrase with
// PBKDF2-SHA256. The passphrase reaches the server via env or a secret file.
// This is the interim v1 secrets store (Sam, 2026-11-16); Vault / an HSM is
// still the open item in CLAUDE.md, and Box is the seam to swap it behind.
//
// Each sealed value is nonce || AES-256-GCM ciphertext. Callers pass AAD that
// binds the value to where it is stored (e.g. agent id + issued_at), so a
// ciphertext copied to another row fails to open.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	keyFormat     = "aegis-secrets-key-v1"
	kdfIterations = 600_000
	keyLen        = 32
	// MinPassphraseLen matches the CA key rule.
	MinPassphraseLen = 16
)

type keyFile struct {
	Format     string `json:"format"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Box seals and opens values under one master key.
type Box struct {
	aead  cipher.AEAD
	keyID string
}

// NewKeyFile generates a random master key and returns it sealed under
// passphrase, ready to write to disk.
func NewKeyFile(passphrase string) ([]byte, error) {
	if len(passphrase) < MinPassphraseLen {
		return nil, fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLen)
	}
	key := make([]byte, keyLen)
	salt := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	wrap, err := passphraseAEAD(passphrase, salt, kdfIterations)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, wrap.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return json.MarshalIndent(keyFile{
		Format: keyFormat, KDF: "pbkdf2-sha256", Iterations: kdfIterations, Salt: salt, Nonce: nonce,
		Ciphertext: wrap.Seal(nil, nonce, key, []byte(keyFormat)),
	}, "", "  ")
}

// Load opens a key file written by NewKeyFile. A wrong passphrase and a
// tampered file both fail.
func Load(data []byte, passphrase string) (*Box, error) {
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse secrets key file: %w", err)
	}
	if kf.Format != keyFormat || kf.KDF != "pbkdf2-sha256" || kf.Iterations < 100_000 {
		return nil, fmt.Errorf("unsupported secrets key file (format %q, kdf %q, iterations %d)", kf.Format, kf.KDF, kf.Iterations)
	}
	wrap, err := passphraseAEAD(passphrase, kf.Salt, kf.Iterations)
	if err != nil {
		return nil, err
	}
	key, err := wrap.Open(nil, kf.Nonce, kf.Ciphertext, []byte(keyFormat))
	if err != nil {
		return nil, errors.New("cannot open secrets key file: wrong passphrase or corrupted file")
	}
	return New(key)
}

// New builds a Box from a raw 32-byte key (tests; Load in production).
func New(key []byte) (*Box, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("secrets key must be %d bytes", keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The key id identifies which master key sealed a row without revealing it.
	sum := sha256.Sum256(append([]byte("aegis-secretbox-key-id\x00"), key...))
	return &Box{aead: aead, keyID: hex.EncodeToString(sum[:8])}, nil
}

// KeyID names the master key (stored next to sealed values).
func (b *Box) KeyID() string { return b.keyID }

// Seal encrypts plaintext bound to aad.
func (b *Box) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize(), b.aead.NonceSize()+len(plaintext)+b.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open decrypts a value from Seal; it fails if the value or aad changed.
func (b *Box) Open(sealed, aad []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n+b.aead.Overhead() {
		return nil, errors.New("sealed value too short")
	}
	out, err := b.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, errors.New("cannot open sealed value: wrong key, wrong binding or corrupted")
	}
	return out, nil
}

func passphraseAEAD(passphrase string, salt []byte, iterations int) (cipher.AEAD, error) {
	k, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
