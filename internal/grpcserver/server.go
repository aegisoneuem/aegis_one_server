// Package grpcserver implements the AgentControlPlane service (proto/agentcontrol/v1)
// that the already-shipped agent (aegis_one_agent-main.zip) connects to.
//
// Each connection is identified by its mTLS client certificate fingerprint via
// internal/identity (trust-on-first-use against the agent-reported device_id).
// Once identified, Heartbeat/PatchScanResult messages are persisted via
// internal/ingest. Dispatch (Dispatch) sends a signed command to a connected
// agent by device_id. Both identity tracking and ingestion no-op (old
// trust-the-message-field, log-only behavior) when no database is configured.
package grpcserver

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	agentcontrolv1 "aegis-one/gen/agentcontrol/v1"
	"aegis-one/internal/commands"
	"aegis-one/internal/identity"
	"aegis-one/internal/ingest"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type Server struct {
	agentcontrolv1.UnimplementedAgentControlPlaneServer
	log      *slog.Logger
	identity *identity.Resolver
	ingest   *ingest.Store
	commands *commands.Store

	mu      sync.Mutex
	clients map[string]chan *agentcontrolv1.ServerMessage // device_id -> outbound queue
}

func New(log *slog.Logger, idr *identity.Resolver, ing *ingest.Store, cmds *commands.Store) *Server {
	return &Server{log: log, identity: idr, ingest: ing, commands: cmds, clients: make(map[string]chan *agentcontrolv1.ServerMessage)}
}

// Dispatch queues msg for delivery to the agent currently connected as deviceID.
// Returns an error if that device has no live connection or its queue is full.
func (s *Server) Dispatch(deviceID string, msg *agentcontrolv1.ServerMessage) error {
	s.mu.Lock()
	ch, ok := s.clients[deviceID]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("no live connection for device %q", deviceID)
	}
	select {
	case ch <- msg:
		return nil
	default:
		return fmt.Errorf("outbound queue full for device %q", deviceID)
	}
}

func (s *Server) register(deviceID string) chan *agentcontrolv1.ServerMessage {
	ch := make(chan *agentcontrolv1.ServerMessage, 16)
	s.mu.Lock()
	s.clients[deviceID] = ch
	s.mu.Unlock()
	return ch
}

func (s *Server) unregister(deviceID string) {
	s.mu.Lock()
	delete(s.clients, deviceID)
	s.mu.Unlock()
}

type registration struct {
	deviceID string
	outbound chan *agentcontrolv1.ServerMessage
}

func (s *Server) Connect(stream agentcontrolv1.AgentControlPlane_ConnectServer) error {
	ctx := stream.Context()

	cert, err := peerCert(ctx)
	if err != nil {
		s.log.Warn("rejecting connect: no usable client certificate", "error", err.Error())
		return status.Error(codes.Unauthenticated, "client certificate required")
	}
	fingerprint := fingerprintOf(cert)

	var known *identity.Known
	if s.identity.Enabled() {
		k, err := s.identity.Lookup(ctx, fingerprint)
		if err != nil {
			s.log.Error("identity lookup failed", "error", err.Error())
			return status.Error(codes.Internal, "identity lookup failed")
		}
		if k != nil && k.Revoked {
			s.log.Warn("rejecting connect: revoked agent", "device_id", k.DeviceID)
			return status.Error(codes.PermissionDenied, "agent revoked")
		}
		known = k
	}
	s.log.Info("agent connected", "fingerprint", shortFingerprint(fingerprint), "known", known != nil)

	registeredCh := make(chan registration, 1)
	recvErrCh := make(chan error, 1)

	go func() {
		deviceID := ""
		resolved := known
		if resolved != nil {
			deviceID = resolved.DeviceID
			registeredCh <- registration{deviceID: deviceID, outbound: s.register(deviceID)}
		}
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErrCh <- err
				return
			}
			if deviceID == "" {
				if dev, hostname, osFamily, agentVersion := identityFieldsOf(msg); dev != "" {
					if s.identity.Enabled() {
						k, err := s.identity.Bootstrap(ctx, fingerprint, cert, dev, hostname, osFamily, agentVersion)
						if err != nil {
							s.log.Warn("identity bootstrap rejected", "device_id", dev, "error", err.Error())
							recvErrCh <- status.Error(codes.PermissionDenied, "identity rejected: "+err.Error())
							return
						}
						resolved = k
					}
					deviceID = dev
					registeredCh <- registration{deviceID: deviceID, outbound: s.register(deviceID)}
					s.log.Info("agent identified", "device_id", deviceID, "bootstrapped", resolved != nil && known == nil)
				}
			} else if dev := deviceIDOf(msg); dev != "" && dev != deviceID {
				s.log.Warn("device_id mismatch on established connection - ignoring claim, keeping bound identity",
					"bound_device_id", deviceID, "claimed_device_id", dev)
			}
			s.handleMessage(ctx, resolved, msg)
		}
	}()

	var deviceID string
	var outbound chan *agentcontrolv1.ServerMessage
	for {
		select {
		case err := <-recvErrCh:
			if deviceID != "" {
				s.unregister(deviceID)
				s.log.Info("agent disconnected", "device_id", deviceID)
			} else {
				s.log.Info("agent disconnected (never identified)")
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err

		case reg := <-registeredCh:
			deviceID, outbound = reg.deviceID, reg.outbound

		case msg := <-outbound: // nil until registered; a nil channel is never selected
			if err := stream.Send(msg); err != nil {
				s.log.Warn("send failed, dropping connection", "device_id", deviceID, "error", err.Error())
				s.unregister(deviceID)
				return err
			}
		}
	}
}

func peerCert(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no peer info in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("peer auth info is not TLS")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate presented")
	}
	return tlsInfo.State.PeerCertificates[0], nil
}

func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func shortFingerprint(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12]
}

func deviceIDOf(msg *agentcontrolv1.AgentMessage) string {
	switch p := msg.GetPayload().(type) {
	case *agentcontrolv1.AgentMessage_Heartbeat:
		return p.Heartbeat.GetDeviceId()
	case *agentcontrolv1.AgentMessage_PatchScanResult:
		return p.PatchScanResult.GetDeviceId()
	default:
		return ""
	}
}

// identityFieldsOf extracts everything Bootstrap needs. PatchScanResult carries a
// device_id but no hostname/agent_version (those come from Heartbeat) - Bootstrap
// falls back to sensible placeholders for those when triggered this way; a
// Heartbeat typically follows shortly and could refine them (not done yet).
func identityFieldsOf(msg *agentcontrolv1.AgentMessage) (deviceID, hostname, osFamily, agentVersion string) {
	switch p := msg.GetPayload().(type) {
	case *agentcontrolv1.AgentMessage_Heartbeat:
		hb := p.Heartbeat
		return hb.GetDeviceId(), hb.GetHostname(), hb.GetOs(), hb.GetAgentVersion()
	case *agentcontrolv1.AgentMessage_PatchScanResult:
		return p.PatchScanResult.GetDeviceId(), "", "windows", ""
	default:
		return "", "", "", ""
	}
}

// handleMessage logs every message, and - once the connection has a resolved
// identity and a database is configured - persists Heartbeat/PatchScanResult via
// internal/ingest. known is nil until this connection's first identifying
// message has been processed (or always nil if identity tracking is disabled).
func (s *Server) handleMessage(ctx context.Context, known *identity.Known, msg *agentcontrolv1.AgentMessage) {
	switch payload := msg.GetPayload().(type) {
	case *agentcontrolv1.AgentMessage_Heartbeat:
		hb := payload.Heartbeat
		s.log.Info("heartbeat",
			"device_id", hb.GetDeviceId(),
			"agent_version", hb.GetAgentVersion(),
			"os", hb.GetOs(),
			"hostname", hb.GetHostname())
		if known != nil {
			if err := s.ingest.Heartbeat(ctx, known, hb); err != nil {
				s.log.Error("persist heartbeat failed", "device_id", known.DeviceID, "error", err.Error())
			}
		}

	case *agentcontrolv1.AgentMessage_CommandResult:
		cr := payload.CommandResult
		s.log.Info("command result",
			"command_id", cr.GetCommandId(),
			"status", cr.GetStatus(),
			"message", cr.GetMessage())
		if known != nil {
			if applied, err := s.commands.ApplyCommandResult(ctx, known.AgentUUID, cr); err != nil {
				s.log.Error("record command result failed", "command_id", cr.GetCommandId(), "error", err.Error())
			} else if !applied {
				s.log.Warn("command result matched no open command for this agent", "command_id", cr.GetCommandId())
			}
		}

	case *agentcontrolv1.AgentMessage_InstallStatus:
		st := payload.InstallStatus
		s.log.Info("install status",
			"command_id", st.GetCommandId(),
			"kb", st.GetKb(),
			"phase", st.GetPhase().String(),
			"exit_code", st.GetExitCode(),
			"reboot_required", st.GetRebootRequired(),
			"reason", st.GetReason())
		if known != nil {
			if applied, err := s.commands.ApplyInstallStatus(ctx, known.AgentUUID, st); err != nil {
				s.log.Error("record install status failed", "command_id", st.GetCommandId(), "error", err.Error())
			} else if !applied {
				s.log.Warn("install status matched no open command for this agent", "command_id", st.GetCommandId())
			}
		}

	case *agentcontrolv1.AgentMessage_PatchScanResult:
		psr := payload.PatchScanResult
		s.log.Info("patch scan result",
			"device_id", psr.GetDeviceId(),
			"build", psr.GetBuild(),
			"architecture", psr.GetArchitecture(),
			"missing_count", len(psr.GetMissing()))
		if known != nil {
			summary, err := s.ingest.PatchScan(ctx, known, psr)
			if err != nil {
				s.log.Error("persist patch scan failed", "device_id", known.DeviceID, "error", err.Error())
			} else {
				s.log.Info("patch scan persisted", "device_id", known.DeviceID,
					"matched", summary.Matched, "unmatched", summary.Unmatched, "marked_installed", summary.MarkedInstalled,
					"sla_assigned", summary.SLAAssigned)
			}
		}

	default:
		s.log.Warn("received message with no recognized payload")
	}
}
