package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// Captured from the agent team's own mockserver (dist/mockserver.exe): the
// "hostname" command it signs on connect, verifiable with the agent's built-in
// dev public key. If CanonicalBytes ever drifts from the agent's encoding, this
// fails.
const (
	agentDevPublicKey = "sluXzV/LHkLeAR+1ldhlAZ+hBofkJWgCrVAkVicYLPg="
	mockSignature     = "HRIpNGDwJu1B08aeNaMaSlIHNBjmLU3M4QsdqkWtH7PbGUPXWNNjVIw1SUhgnyqs32SC1fhgjBl/qOopwOGFAw=="
)

func TestVerifiesAgentTeamSignature(t *testing.T) {
	pub, _ := base64.StdEncoding.DecodeString(agentDevPublicKey)
	sig, _ := base64.StdEncoding.DecodeString(mockSignature)
	if !VerifyCommand(ed25519.PublicKey(pub), "hostname", "cmd-001", nil, sig) {
		t.Fatal("CanonicalBytes does not match the agent's encoding")
	}
	// The signature must bind type and id, not just the payload.
	if VerifyCommand(ed25519.PublicKey(pub), "whoami", "cmd-001", nil, sig) {
		t.Fatal("signature verified under a different command type")
	}
	if VerifyCommand(ed25519.PublicKey(pub), "hostname", "cmd-002", nil, sig) {
		t.Fatal("signature verified under a different command id")
	}
}

func TestSignRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := []byte{0x0a, 0x03, 'K', 'B', '1'}
	sig := SignCommand(priv, "install_patch", "a170fd7b-b6f8-449a-b82f-78ea0ba0da71", payload)
	if !VerifyCommand(pub, "install_patch", "a170fd7b-b6f8-449a-b82f-78ea0ba0da71", payload, sig) {
		t.Fatal("round trip failed")
	}
	if VerifyCommand(pub, "install_patch", "a170fd7b-b6f8-449a-b82f-78ea0ba0da71", append(payload, 0), sig) {
		t.Fatal("tampered payload verified")
	}
}

// Length prefixes make field boundaries unambiguous: ("ab","c") and ("a","bc")
// must not produce the same signed bytes.
func TestCanonicalBytesBoundaries(t *testing.T) {
	if string(CanonicalBytes("ab", "c", nil)) == string(CanonicalBytes("a", "bc", nil)) {
		t.Fatal("field boundaries are ambiguous")
	}
}
