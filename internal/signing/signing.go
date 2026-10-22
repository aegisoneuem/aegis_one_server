// Package signing loads the Ed25519 command-signing private key and signs
// commands exactly the way the agent verifies them. The matching public key is
// configured on the agent (AEGIS_CMD_VERIFY_KEY / AEGIS_CMD_VERIFY_KEY_FILE).
//
// The private key lives in a local gitignored file, not Vault - CLAUDE.md lists
// the real v1 secrets store as an open item; this is a stopgap, not the answer.
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// canonicalPrefix domain-separates command signatures from anything else the
// same key might ever sign.
const canonicalPrefix = "aegisone-cmd-sig-v1"

// CanonicalBytes is the exact byte string the agent verifies a Command's
// signature over (agent team's aegis_one_proto/commandsign.CanonicalBytes):
//
//	"aegisone-cmd-sig-v1" | u32be(len(type)) | type | u32be(len(id)) | id | u32be(len(payload)) | payload
//
// Binding type and command_id (not just the payload) stops a valid signature
// being replayed under a different command type or id. Recovered from the
// compiled agent/mockserver (that package's source wasn't available) and
// verified against signatures produced by the agent team's own mockserver - see
// signing_test.go.
func CanonicalBytes(cmdType, commandID string, payload []byte) []byte {
	b := make([]byte, 0, len(canonicalPrefix)+12+len(cmdType)+len(commandID)+len(payload))
	b = append(b, canonicalPrefix...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(cmdType)))
	b = append(b, cmdType...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(commandID)))
	b = append(b, commandID...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(payload)))
	b = append(b, payload...)
	return b
}

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

// SignCommand returns the signature to put in Command.signature.
func SignCommand(key ed25519.PrivateKey, cmdType, commandID string, payload []byte) []byte {
	return ed25519.Sign(key, CanonicalBytes(cmdType, commandID, payload))
}

// VerifyCommand mirrors the agent's check; used in tests.
func VerifyCommand(pub ed25519.PublicKey, cmdType, commandID string, payload, sig []byte) bool {
	return ed25519.Verify(pub, CanonicalBytes(cmdType, commandID, payload), sig)
}
