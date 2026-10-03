// Package pushapi is a minimal, internal-only HTTP trigger for pushing a signed
// command to a connected agent. There is no admin UI/API layer yet, so this
// exists purely so a signed dispatch can be tested/operated from curl; it is NOT
// meant to be exposed outside the management network.
//
// It does not persist to agent_commands (that table's agent_id is a UUID FK into
// agents, which assumes a proper enrollment flow this simplified agent contract
// doesn't have - see memory/project notes). A command sent here is fire-and-forget
// at the DB level: delivery still happens over the signed gRPC channel, just
// without an audit row yet.
package pushapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"

	agentcontrolv1 "aegis-one/gen/agentcontrol/v1"
	"aegis-one/internal/signing"

	"google.golang.org/protobuf/proto"
)

type Dispatcher interface {
	Dispatch(deviceID string, msg *agentcontrolv1.ServerMessage) error
}

type Handler struct {
	dispatcher Dispatcher
	signingKey ed25519.PrivateKey // nil if unavailable; handler 503s instead of crashing
	log        *slog.Logger
}

func New(dispatcher Dispatcher, signingKey ed25519.PrivateKey, log *slog.Logger) *Handler {
	return &Handler{dispatcher: dispatcher, signingKey: signingKey, log: log}
}

// ServeHTTP handles POST /internal/push.
//
// Generic command:   ?device_id=X&type=hostname
// Install a patch:   ?device_id=X&type=install_patch&kb=KB123&file_path=C:\...\patch.msu[&expected_hash=...&hash_algorithm=sha256]
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if h.signingKey == nil {
		http.Error(w, "command signing key not loaded on this server (run cmd/keygen)", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	deviceID := q.Get("device_id")
	cmdType := q.Get("type")
	if deviceID == "" || cmdType == "" {
		http.Error(w, "device_id and type are required", http.StatusBadRequest)
		return
	}

	var payload []byte
	switch cmdType {
	case "install_patch":
		kb := q.Get("kb")
		filePath := q.Get("file_path")
		if kb == "" || filePath == "" {
			http.Error(w, "install_patch requires kb and file_path", http.StatusBadRequest)
			return
		}
		spec := &agentcontrolv1.InstallPatchSpec{
			Kb:            kb,
			FilePath:      filePath,
			ExpectedHash:  q.Get("expected_hash"),
			HashAlgorithm: q.Get("hash_algorithm"),
		}
		marshaled, err := proto.Marshal(spec)
		if err != nil {
			http.Error(w, "marshal install spec: "+err.Error(), http.StatusInternalServerError)
			return
		}
		payload = marshaled
	default:
		payload = []byte(q.Get("payload"))
	}

	commandID, err := randomID()
	if err != nil {
		http.Error(w, "generate command id: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cmd := &agentcontrolv1.Command{
		CommandId: commandID,
		Type:      cmdType,
		Payload:   payload,
		Signature: signing.Sign(h.signingKey, payload),
	}
	msg := &agentcontrolv1.ServerMessage{Payload: &agentcontrolv1.ServerMessage_Command{Command: cmd}}

	if err := h.dispatcher.Dispatch(deviceID, msg); err != nil {
		h.log.Warn("push failed", "device_id", deviceID, "command_id", commandID, "error", err.Error())
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	h.log.Info("command pushed", "device_id", deviceID, "command_id", commandID, "type", cmdType)
	fmt.Fprintf(w, "queued command_id=%s for device_id=%s\n", commandID, deviceID)
}

func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "cmd-" + hex.EncodeToString(b), nil
}
