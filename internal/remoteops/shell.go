package remoteops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/commands"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Shell defaults and bounds (the agent's own defaults: TTL 60 s, idle 600 s,
// max 3600 s).
const (
	shellTTLDefault  = 60
	shellIdleDefault = 600
	shellMaxDefault  = 3600
	shellMaxDuration = 4 * 3600
	shellOutputKeep  = 4 << 20 // output kept in memory for polling
	shellPollMax     = 25 * time.Second
)

// Shells brokers interactive shells: the operator opens one through the API
// (open_shell goes to the agent with a random, single-use session id), the
// agent dials ShellSession and names that id, and from then on operator input
// goes to the agent and the shell's output is buffered for the operator to
// poll. Only the API client that opened a session can use it. Everything
// typed and printed is recorded in a transcript under <content dir>/shell/.
type Shells struct {
	pool   *pgxpool.Pool
	dir    string
	sender *commands.Sender
	log    *slog.Logger

	mu       sync.Mutex
	sessions map[string]*session
}

func NewShells(pool *pgxpool.Pool, contentDir string, sender *commands.Sender, log *slog.Logger) *Shells {
	return &Shells{pool: pool, dir: contentDir, sender: sender, log: log, sessions: map[string]*session{}}
}

type session struct {
	id, deviceUUID, agentUUID, deviceID, clientID string
	ttl, idle, max                                int32
	created                                       time.Time

	mu         sync.Mutex
	state      string // opening | active | closed | failed
	input      chan *aegisonev1.ShellInput
	chunks     []OutputChunk
	keptBytes  int
	nextSeq    int64
	notify     chan struct{} // closed and replaced on every new chunk / state change
	exitCode   *int32
	reason     string
	transcript *os.File
	bytesIn    int64
	bytesOut   int64
}

// OutputChunk is one piece of shell output for the operator.
type OutputChunk struct {
	Seq    int64  `json:"seq"`
	Stream string `json:"stream"` // stdout | stderr
	Data   string `json:"data"`
}

// OpenRequest opens a shell on one device.
type OpenRequest struct {
	DeviceID           string
	ClientID           string
	ClientName         string
	TTLSeconds         int32
	IdleTimeoutSeconds int32
	MaxDurationSeconds int32
}

// Opened describes a session being opened.
type Opened struct {
	SessionID string `json:"session_id"`
	CommandID string `json:"command_id"`
	Status    string `json:"status"`
}

func (sh *Shells) Open(ctx context.Context, r OpenRequest) (*Opened, error) {
	ttl, idle, max := orDefault(r.TTLSeconds, shellTTLDefault), orDefault(r.IdleTimeoutSeconds, shellIdleDefault), orDefault(r.MaxDurationSeconds, shellMaxDefault)
	if ttl < 10 || ttl > 300 || idle < 30 || idle > 3600 || max < 60 || max > shellMaxDuration {
		return nil, userErr("ttl_seconds 10..300, idle_timeout_seconds 30..3600, max_duration_seconds 60..%d", shellMaxDuration)
	}
	var deviceUUID, agentUUID string
	err := sh.pool.QueryRow(ctx, `
		SELECT d.id, a.id FROM devices d JOIN agents a ON a.device_id = d.id AND a.revoked_at IS NULL
		WHERE d.agent_reported_id = $1`, r.DeviceID).Scan(&deviceUUID, &agentUUID)
	if err != nil {
		return nil, userErr("unknown device_id %q", r.DeviceID)
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(raw[:])
	transcriptRel := filepath.ToSlash(filepath.Join("shell", id+".log"))
	if err := os.MkdirAll(filepath.Join(sh.dir, "shell"), 0o750); err != nil {
		return nil, err
	}
	tf, err := os.OpenFile(filepath.Join(sh.dir, filepath.FromSlash(transcriptRel)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	s := &session{id: id, deviceUUID: deviceUUID, agentUUID: agentUUID, deviceID: r.DeviceID, clientID: r.ClientID,
		ttl: ttl, idle: idle, max: max, created: time.Now(), state: "opening",
		input: make(chan *aegisonev1.ShellInput, 64), notify: make(chan struct{}), transcript: tf}
	fmt.Fprintf(tf, "# Aegis One shell session %s\n# device %s, opened by %s at %s\n", id, r.DeviceID, r.ClientName, time.Now().UTC().Format(time.RFC3339))
	if _, err := sh.pool.Exec(ctx, `
		INSERT INTO shell_sessions (id, device_id, agent_id, created_by_api_client_id, ttl_seconds, idle_timeout_seconds,
		                            max_duration_seconds, transcript_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, deviceUUID, agentUUID, r.ClientID, ttl, idle, max, transcriptRel); err != nil {
		tf.Close()
		return nil, err
	}
	sh.mu.Lock()
	sh.sessions[id] = s
	sh.mu.Unlock()

	wire, err := proto.Marshal(&aegisonev1.OpenShellSpec{SessionId: id, TtlSeconds: ttl, IdleTimeoutSeconds: idle,
		MaxDurationSeconds: max, IssuedAt: time.Now().Unix()})
	if err != nil {
		return nil, err
	}
	sent, err := sh.sender.Send(ctx, commands.SendRequest{
		DeviceID: r.DeviceID, Type: "open_shell", Wire: wire,
		// The session id is a credential for the stream; the audit keeps a prefix.
		Audit:    map[string]any{"session": id[:12], "ttl_seconds": ttl, "idle_timeout_seconds": idle, "max_duration_seconds": max},
		ClientID: r.ClientID, ClientName: r.ClientName, Actor: "api_client:" + r.ClientName,
	})
	if err != nil {
		sh.end(s, "failed", nil, "server error")
		return nil, err
	}
	out := &Opened{SessionID: id, CommandID: sent.CommandID, Status: sent.Status}
	if sent.CommandID != "" {
		sh.pool.Exec(ctx, `UPDATE shell_sessions SET command_id = $2 WHERE id = $1`, id, sent.CommandID) //nolint:errcheck
	}
	if sent.Status != "dispatched" {
		sh.end(s, "failed", nil, "open_shell not sent: "+sent.Status)
		return out, nil
	}
	out.Status = "opening"
	sh.log.Info("shell session opening", "session", id[:12], "device_id", r.DeviceID, "client", r.ClientName)
	return out, nil
}

// Attach serves one agent ShellSession stream. The first message must name a
// session that is still opening, belongs to this agent and is within its TTL.
func (sh *Shells) Attach(stream aegisonev1.AgentControlPlane_ShellSessionServer, agentUUID string) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	id := first.GetSessionId()
	if id == "" {
		return status.Error(codes.InvalidArgument, "session_id required")
	}
	sh.mu.Lock()
	s := sh.sessions[id]
	sh.mu.Unlock()
	if s == nil || s.agentUUID != agentUUID {
		return status.Error(codes.PermissionDenied, "unknown or already-consumed session_id")
	}
	s.mu.Lock()
	if s.state != "opening" || time.Since(s.created) > time.Duration(s.ttl)*time.Second {
		s.mu.Unlock()
		return status.Error(codes.PermissionDenied, "unknown or already-consumed session_id")
	}
	s.state = "active"
	s.signalLocked()
	s.mu.Unlock()
	sh.pool.Exec(stream.Context(), `UPDATE shell_sessions SET status = 'active', opened_at = now() WHERE id = $1`, id) //nolint:errcheck
	sh.log.Info("shell session active", "session", id[:12], "device_id", s.deviceID)

	ctx := stream.Context()
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				sendErr <- ctx.Err()
				return
			case in, ok := <-s.input:
				if !ok {
					sendErr <- nil
					return
				}
				if err := stream.Send(in); err != nil {
					sendErr <- err
					return
				}
			}
		}
	}()
	for {
		msg, err := stream.Recv()
		if err != nil {
			sh.end(s, "closed", nil, "stream ended")
			return nil
		}
		if d := msg.GetStdout(); len(d) > 0 {
			s.output("stdout", d)
		}
		if d := msg.GetStderr(); len(d) > 0 {
			s.output("stderr", d)
		}
		if msg.GetClosed() {
			code := msg.GetExitCode()
			sh.end(s, "closed", &code, msg.GetReason())
			return nil
		}
		select {
		case err := <-sendErr:
			if err != nil {
				sh.end(s, "closed", nil, "send to agent failed")
				return nil
			}
		default:
		}
	}
}

func (s *session) output(stream string, d []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bytesOut += int64(len(d))
	fmt.Fprintf(s.transcript, "[%s %s] %s\n", stream, time.Now().UTC().Format("15:04:05"), d)
	s.nextSeq++
	s.chunks = append(s.chunks, OutputChunk{Seq: s.nextSeq, Stream: stream, Data: string(d)})
	s.keptBytes += len(d)
	for s.keptBytes > shellOutputKeep && len(s.chunks) > 1 {
		s.keptBytes -= len(s.chunks[0].Data)
		s.chunks = s.chunks[1:]
	}
	s.signalLocked()
}

func (s *session) signalLocked() {
	close(s.notify)
	s.notify = make(chan struct{})
}

// end finishes a session once.
func (sh *Shells) end(s *session, state string, exitCode *int32, reason string) {
	s.mu.Lock()
	if s.state == "closed" || s.state == "failed" {
		s.mu.Unlock()
		return
	}
	s.state, s.exitCode, s.reason = state, exitCode, reason
	fmt.Fprintf(s.transcript, "# session %s at %s: %s\n", state, time.Now().UTC().Format(time.RFC3339), reason)
	s.transcript.Close()
	in, out := s.bytesIn, s.bytesOut
	close(s.input)
	s.signalLocked()
	s.mu.Unlock()
	sh.pool.Exec(context.Background(), `
		UPDATE shell_sessions SET status = $2, exit_code = $3, close_reason = $4, bytes_in = $5, bytes_out = $6, closed_at = now()
		WHERE id = $1`, s.id, state, exitCode, reason, in, out) //nolint:errcheck
	sh.log.Info("shell session ended", "session", s.id[:12], "device_id", s.deviceID, "state", state, "reason", reason)
	// Keep the ended session briefly so the operator can read the last output.
	time.AfterFunc(10*time.Minute, func() {
		sh.mu.Lock()
		delete(sh.sessions, s.id)
		sh.mu.Unlock()
	})
}

var errNoSession = errors.New("no such session for this API client")

func (sh *Shells) owned(id, clientID string) (*session, error) {
	sh.mu.Lock()
	s := sh.sessions[id]
	sh.mu.Unlock()
	if s == nil || s.clientID != clientID {
		return nil, errNoSession
	}
	return s, nil
}

// Input sends operator keystrokes (stdin) or a control ("close" / "break",
// both end the shell) to an active session.
func (sh *Shells) Input(id, clientID string, stdin []byte, control string) error {
	s, err := sh.owned(id, clientID)
	if err != nil {
		return err
	}
	if control != "" && control != "close" && control != "break" {
		return userErr("control must be close or break")
	}
	if len(stdin) > 64<<10 {
		return userErr("at most 64 KiB of input per request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != "active" {
		return userErr("session is %s", s.state)
	}
	if len(stdin) > 0 {
		s.bytesIn += int64(len(stdin))
		fmt.Fprintf(s.transcript, "[stdin %s] %s\n", time.Now().UTC().Format("15:04:05"), stdin)
	}
	if control != "" {
		fmt.Fprintf(s.transcript, "[control %s] %s\n", time.Now().UTC().Format("15:04:05"), control)
	}
	select {
	case s.input <- &aegisonev1.ShellInput{Stdin: stdin, Control: control}:
		return nil
	default:
		return userErr("input queue is full; retry")
	}
}

// OutputView is what a poll returns.
type OutputView struct {
	SessionID string        `json:"session_id"`
	State     string        `json:"state"`
	ExitCode  *int32        `json:"exit_code,omitempty"`
	Reason    string        `json:"reason,omitempty"`
	Chunks    []OutputChunk `json:"chunks"`
	NextAfter int64         `json:"next_after"` // pass back as ?after=
}

// Output returns output after seq, waiting up to wait for some (long poll).
func (sh *Shells) Output(ctx context.Context, id, clientID string, after int64, wait time.Duration) (*OutputView, error) {
	s, err := sh.owned(id, clientID)
	if err != nil {
		return nil, err
	}
	if wait > shellPollMax {
		wait = shellPollMax
	}
	deadline := time.After(wait)
	for {
		s.mu.Lock()
		v := &OutputView{SessionID: id, State: s.state, ExitCode: s.exitCode, Reason: s.reason, Chunks: []OutputChunk{}, NextAfter: after}
		for _, c := range s.chunks {
			if c.Seq > after {
				v.Chunks = append(v.Chunks, c)
				v.NextAfter = c.Seq
			}
		}
		notify := s.notify
		done := s.state == "closed" || s.state == "failed"
		s.mu.Unlock()
		if len(v.Chunks) > 0 || done {
			return v, nil
		}
		select {
		case <-notify:
		case <-deadline:
			return v, nil
		case <-ctx.Done():
			return v, nil
		}
	}
}

// Run fails sessions the agent never attached to within their TTL.
func (sh *Shells) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		sh.mu.Lock()
		var stale []*session
		for _, s := range sh.sessions {
			s.mu.Lock()
			if s.state == "opening" && time.Since(s.created) > time.Duration(s.ttl+10)*time.Second {
				stale = append(stale, s)
			}
			s.mu.Unlock()
		}
		sh.mu.Unlock()
		for _, s := range stale {
			sh.end(s, "failed", nil, "the agent did not attach within the TTL")
		}
	}
}

func orDefault(v, def int32) int32 {
	if v == 0 {
		return def
	}
	return v
}
