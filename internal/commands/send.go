package commands

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/signing"
)

// Dispatcher hands a message to a connected agent.
type Dispatcher interface {
	Dispatch(deviceID string, msg *aegisonev1.ServerMessage) error
	Connected(deviceID string) bool
}

// Sender signs, records and dispatches one command to one online device. It
// is the shared path for direct actions (reboot, run_command, collect_file,
// ...): the agent_commands row and its audit_log entry are written before
// anything is sent.
type Sender struct {
	Store *Store
	Disp  Dispatcher
	Key   ed25519.PrivateKey
	KeyID string
}

// SendRequest is one command for one device.
type SendRequest struct {
	DeviceID   string         // agent-reported device id
	Type       string         // command type, e.g. "reboot"
	Wire       []byte         // signed payload as sent
	Audit      map[string]any // what is stored in agent_commands.payload; never secrets
	ClientID   string
	ClientName string
	Actor      string // Command.actor, e.g. "api_client:ops"
}

// Sent says what happened to one device's command.
type Sent struct {
	DeviceID  string `json:"device_id"`
	CommandID string `json:"command_id,omitempty"`
	// dispatched | offline | unknown_device | unsupported | failed
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Send delivers r. A device that is offline, unknown, or whose agent doesn't
// advertise the command type gets no command at all: these commands carry no
// expiry, so a reboot or a script must not run days later on reconnect.
func (s *Sender) Send(ctx context.Context, r SendRequest) (Sent, error) {
	out := Sent{DeviceID: r.DeviceID}
	if s.Key == nil || s.KeyID == "" {
		return out, errors.New("command signing key not loaded/registered on this server")
	}
	agentUUID, err := s.Store.AgentForDevice(ctx, r.DeviceID)
	if errors.Is(err, ErrNoAgent) {
		out.Status = "unknown_device"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	ok, err := s.Store.Supports(ctx, agentUUID, r.Type)
	if err != nil {
		return out, err
	}
	if !ok {
		out.Status, out.Error = "unsupported", "the agent does not advertise "+r.Type
		return out, nil
	}
	if !s.Disp.Connected(r.DeviceID) {
		out.Status = "offline"
		return out, nil
	}
	id, err := NewID()
	if err != nil {
		return out, err
	}
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return out, err
	}
	sig := signing.SignCommand(s.Key, r.Type, id, r.Wire)
	cmdID, existing, err := s.Store.Create(ctx, Issue{
		ID: id, AgentUUID: agentUUID, DeviceID: r.DeviceID, Type: r.Type, Payload: r.Audit,
		Signature: sig, SigningKeyID: s.KeyID, IdempotencyKey: "action:" + hex.EncodeToString(rnd[:]),
		IssuedByAPIClientID: r.ClientID, IssuedByLabel: r.ClientName,
	})
	if err != nil {
		return out, err
	}
	if existing != nil {
		return out, fmt.Errorf("idempotency key collision with command %s", existing.ID)
	}
	out.CommandID = cmdID
	msg := &aegisonev1.ServerMessage{Payload: &aegisonev1.ServerMessage_Command{Command: Envelope(cmdID, r.Type, r.Wire, sig, r.Actor)}}
	if err := s.Disp.Dispatch(r.DeviceID, msg); err != nil {
		_ = s.Store.MarkFailed(ctx, cmdID, err.Error())
		out.Status, out.Error = "failed", err.Error()
		return out, nil
	}
	_ = s.Store.MarkDispatched(ctx, cmdID)
	out.Status = "dispatched"
	return out, nil
}

// Supports reports whether the agent advertises cmdType. An agent that sends
// no capability list (older builds) is not filtered.
func (s *Store) Supports(ctx context.Context, agentUUID, cmdType string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT cardinality(agent_capabilities) = 0 OR $2 = ANY(agent_capabilities) FROM agents WHERE id = $1`,
		agentUUID, cmdType).Scan(&ok)
	return ok, err
}
