// Package pushapi is a minimal internal HTTP trigger for pushing a signed
// command to a connected agent (no admin UI exists yet). It must be mounted
// behind apiauth.Require: install_patch needs 'patch.deploy', any other command
// type needs 'agent.command' (remote command execution - admin-only by default).
//
// Every push is recorded in agent_commands (+ audit_log) BEFORE it is sent, and
// the row's UUID is the wire command_id. A database is therefore required -
// un-audited command dispatch to endpoints is refused.
package pushapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	agentcontrolv1 "aegis-one/gen/agentcontrol/v1"
	"aegis-one/internal/apiauth"
	"aegis-one/internal/commands"
	"aegis-one/internal/signing"

	"google.golang.org/protobuf/proto"
)

type Dispatcher interface {
	Dispatch(deviceID string, msg *agentcontrolv1.ServerMessage) error
}

type Handler struct {
	dispatcher   Dispatcher
	store        *commands.Store // nil when no database is configured
	signingKey   ed25519.PrivateKey
	signingKeyID string
	log          *slog.Logger
}

func New(dispatcher Dispatcher, store *commands.Store, signingKey ed25519.PrivateKey, signingKeyID string, log *slog.Logger) *Handler {
	return &Handler{dispatcher: dispatcher, store: store, signingKey: signingKey, signingKeyID: signingKeyID, log: log}
}

// ServeHTTP handles POST /internal/push.
//
// Generic command:   ?device_id=X&type=hostname
// Install a patch:   ?device_id=X&type=install_patch&kb=KB123&file_path=C:\...\patch.msu[&expected_hash=...&hash_algorithm=sha256]
// Optional on both:  &idempotency_key=K  - a repeat with the same key is NOT re-sent.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if h.store == nil {
		http.Error(w, "database required: commands are only dispatched with an agent_commands audit row", http.StatusServiceUnavailable)
		return
	}
	if h.signingKey == nil || h.signingKeyID == "" {
		http.Error(w, "command signing key not loaded/registered on this server (run cmd/keygen)", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	deviceID := q.Get("device_id")
	cmdType := q.Get("type")
	if deviceID == "" || cmdType == "" {
		http.Error(w, "device_id and type are required", http.StatusBadRequest)
		return
	}

	caller, ok := apiauth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	needed := apiauth.PermAgentCommand
	if cmdType == "install_patch" {
		needed = apiauth.PermPatchDeploy
	}
	if !caller.Can(needed) {
		apiauth.Deny(w, h.log, caller, needed, r)
		return
	}

	var wirePayload []byte
	var auditPayload map[string]any
	switch cmdType {
	case "install_patch":
		spec := &agentcontrolv1.InstallPatchSpec{
			Kb:            q.Get("kb"),
			FilePath:      q.Get("file_path"),
			ExpectedHash:  q.Get("expected_hash"),
			HashAlgorithm: q.Get("hash_algorithm"),
		}
		if spec.Kb == "" || spec.FilePath == "" {
			http.Error(w, "install_patch requires kb and file_path", http.StatusBadRequest)
			return
		}
		marshaled, err := proto.Marshal(spec)
		if err != nil {
			http.Error(w, "marshal install spec: "+err.Error(), http.StatusInternalServerError)
			return
		}
		wirePayload = marshaled
		auditPayload = map[string]any{
			"kb": spec.Kb, "file_path": spec.FilePath,
			"expected_hash": spec.ExpectedHash, "hash_algorithm": spec.HashAlgorithm,
		}
	default:
		wirePayload = []byte(q.Get("payload"))
		auditPayload = map[string]any{"payload": q.Get("payload")}
	}

	ctx := r.Context()
	agentUUID, err := h.store.AgentForDevice(ctx, deviceID)
	if errors.Is(err, commands.ErrNoAgent) {
		http.Error(w, fmt.Sprintf("unknown device_id %q (never connected, or its agent is revoked)", deviceID), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "resolve agent: "+err.Error(), http.StatusInternalServerError)
		return
	}

	idemKey := q.Get("idempotency_key")
	if idemKey == "" {
		if idemKey, err = randomKey(); err != nil {
			http.Error(w, "generate idempotency key: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	signature := signing.Sign(h.signingKey, wirePayload)
	commandID, existing, err := h.store.Create(ctx, commands.Issue{
		AgentUUID: agentUUID, DeviceID: deviceID, Type: cmdType, Payload: auditPayload,
		Signature: signature, SigningKeyID: h.signingKeyID, IdempotencyKey: idemKey,
		IssuedByAPIClientID: caller.ClientID, IssuedByLabel: caller.ClientName,
	})
	if err != nil {
		http.Error(w, "record command: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if existing != nil {
		http.Error(w, fmt.Sprintf("idempotency_key already used by command_id=%s (status=%s); not re-sent", existing.ID, existing.Status), http.StatusConflict)
		return
	}

	msg := &agentcontrolv1.ServerMessage{Payload: &agentcontrolv1.ServerMessage_Command{Command: &agentcontrolv1.Command{
		CommandId: commandID, Type: cmdType, Payload: wirePayload, Signature: signature,
	}}}
	if err := h.dispatcher.Dispatch(deviceID, msg); err != nil {
		if mErr := h.store.MarkFailed(ctx, commandID, err.Error()); mErr != nil {
			h.log.Error("could not mark command failed", "command_id", commandID, "error", mErr.Error())
		}
		h.log.Warn("push failed", "device_id", deviceID, "command_id", commandID, "error", err.Error())
		http.Error(w, fmt.Sprintf("%v (recorded as command_id=%s, status=failed)", err, commandID), http.StatusConflict)
		return
	}
	if err := h.store.MarkDispatched(ctx, commandID); err != nil {
		h.log.Error("could not mark command dispatched", "command_id", commandID, "error", err.Error())
	}

	h.log.Info("command pushed", "device_id", deviceID, "command_id", commandID, "type", cmdType, "client", caller.ClientName)
	fmt.Fprintf(w, "dispatched command_id=%s to device_id=%s\n", commandID, deviceID)
}

func randomKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "auto-" + hex.EncodeToString(b), nil
}
