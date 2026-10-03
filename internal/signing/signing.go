// Package signing loads the Ed25519 command-signing private key and signs
// command payloads. The matching public key is what must be hardcoded into the
// agent binary (or, once the locked spec's TrustedKeySet exists, delivered over
// the wire) for signature verification to succeed.
//
// The private key lives in a local gitignored file, not Vault - CLAUDE.md lists
// the real v1 secrets store as an open item; this is a stopgap, not the answer.
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// LoadPrivateKey reads a base64-encoded Ed25519 private key (as written by
// cmd/keygen) from path.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key %q (run cmd/keygen first?): %w", path, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode signing key %q: %w", path, err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key %q: expected %d bytes, got %d", path, ed25519.PrivateKeySize, len(decoded))
	}
	return ed25519.PrivateKey(decoded), nil
}

// Sign returns the Ed25519 signature of payload.
func Sign(key ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(key, payload)
}
