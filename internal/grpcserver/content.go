package grpcserver

// Content delivery to agents over the agent channel (the agent calls it
// "peer-cache"): the agent never downloads from the internet.
//
//   - CabManifest (server -> agent on Connect): {version, sha256} of the current
//     wsusscn2.cab. The agent keeps the version of its own copy and, when they
//     differ, calls FetchContent{kind:"cab", id:version, sha256}, verifies the
//     SHA-256, swaps the file in and runs a full scan. We use the SHA-256 itself
//     as the version, so equal versions mean identical bytes.
//   - FetchContent streams the file in chunks.
//
// Integrity is the SHA-256 in the manifest, which arrives over mTLS from this
// server. The manifest itself is not Ed25519-signed: the agent's contract has no
// signature field for it.
//
// kind "patch" and "package" (stage_patch / software_deploy installers) need a
// content store that doesn't exist yet and are refused with Unimplemented.

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/cabfeed"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// contentChunkSize is well under gRPC's default 4 MiB message limit.
const contentChunkSize = 256 << 10

type contentStore struct {
	pool  *pgxpool.Pool
	dir   string
	slots chan struct{} // one token per in-flight FetchContent

	mu  sync.Mutex
	cab *cabfeed.Catalog // current cab as of the last WatchCab check; nil if none
}

// EnableContent turns on FetchContent and CabManifest. dir is the server's
// content directory (AEGIS_CONTENT_DIR); at most maxStreams downloads run at
// once, the rest wait. Call before serving; then run WatchCab.
func (s *Server) EnableContent(pool *pgxpool.Pool, dir string, maxStreams int) {
	s.content = &contentStore{pool: pool, dir: dir, slots: make(chan struct{}, maxStreams)}
}

// WatchCab polls for the current scan cab every interval until ctx ends. When
// it changes (the feed scheduler downloaded a new one), every connected agent
// gets the new CabManifest; agents connecting later get it in register.
func (s *Server) WatchCab(ctx context.Context, interval time.Duration) {
	check := func() {
		cat, err := cabfeed.Current(ctx, s.content.pool)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("cab watch: look up current cab", "error", err.Error())
			}
			return
		}
		s.content.mu.Lock()
		prev := s.content.cab
		s.content.cab = cat
		s.content.mu.Unlock()
		if cat == nil || (prev != nil && prev.SHA256 == cat.SHA256) {
			return
		}
		if prev == nil {
			s.log.Info("cab manifest: serving scan cab", "sha256", cat.SHA256, "size_bytes", cat.SizeBytes)
		}
		sent, skipped := s.broadcast(s.cabManifestMessage())
		if prev != nil || sent > 0 {
			s.log.Info("cab manifest: new scan cab announced", "sha256", cat.SHA256, "agents", sent, "queue_full", skipped)
		}
	}
	check()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

// cabManifestMessage is the CabManifest for the current cab, or nil if content
// delivery is off or there is no cab yet.
func (s *Server) cabManifestMessage() *aegisonev1.ServerMessage {
	if s.content == nil {
		return nil
	}
	s.content.mu.Lock()
	cat := s.content.cab
	s.content.mu.Unlock()
	if cat == nil {
		return nil
	}
	return &aegisonev1.ServerMessage{Payload: &aegisonev1.ServerMessage_CabManifest{
		CabManifest: &aegisonev1.CabManifest{Version: cat.SHA256, Sha256: cat.SHA256},
	}}
}

// broadcast queues msg to every connected agent without blocking. An agent
// whose queue is full is skipped; it gets the current manifest on reconnect.
func (s *Server) broadcast(msg *aegisonev1.ServerMessage) (sent, skipped int) {
	if msg == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.clients {
		select {
		case ch <- msg:
			sent++
		default:
			skipped++
		}
	}
	return sent, skipped
}

func (s *Server) FetchContent(req *aegisonev1.ContentRequest, stream aegisonev1.AgentControlPlane_FetchContentServer) error {
	if s.content == nil {
		return status.Error(codes.Unavailable, "content delivery is not enabled on this server")
	}
	ctx := stream.Context()
	known, err := s.knownAgent(ctx, "fetch content")
	if err != nil {
		return err
	}
	switch req.GetKind() {
	case "cab":
	case "patch", "package":
		return status.Errorf(codes.Unimplemented, "content kind %q is not served yet", req.GetKind())
	default:
		return status.Errorf(codes.InvalidArgument, "unknown content kind %q", req.GetKind())
	}

	version := strings.ToLower(strings.TrimSpace(req.GetId()))
	if !isSHA256Hex(version) {
		return status.Error(codes.InvalidArgument, "cab id must be the version from the cab manifest")
	}
	if want := strings.ToLower(strings.TrimSpace(req.GetSha256())); want != "" && want != version {
		return status.Error(codes.InvalidArgument, "sha256 does not match the requested cab version")
	}
	cat, err := cabfeed.ByHash(ctx, s.content.pool, version)
	if err != nil {
		s.log.Error("fetch content: look up cab", "error", err.Error())
		return status.Error(codes.Internal, "content lookup failed")
	}
	if cat == nil {
		return status.Error(codes.NotFound, "cab version not available (superseded); wait for the next manifest")
	}

	// Wait for a download slot rather than refusing: the agent only retries
	// a failed cab fetch when it gets another manifest.
	select {
	case s.content.slots <- struct{}{}:
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	}
	defer func() { <-s.content.slots }()

	path := filepath.Join(s.content.dir, filepath.FromSlash(cat.FileName))
	f, err := os.Open(path)
	if err != nil {
		s.log.Error("fetch content: cab file missing on disk", "file", cat.FileName, "error", err.Error())
		return status.Error(codes.Internal, "content unavailable")
	}
	defer f.Close()
	// Fail closed on a truncated/replaced file; the agent would reject it on
	// the hash anyway, but only after the whole download.
	if fi, err := f.Stat(); err != nil || fi.Size() != cat.SizeBytes {
		s.log.Error("fetch content: cab file size does not match catalog", "file", cat.FileName, "want_bytes", cat.SizeBytes)
		return status.Error(codes.Internal, "content unavailable")
	}

	start := time.Now()
	s.log.Info("fetch content: sending cab", "device_id", known.DeviceID, "sha256", cat.SHA256, "size_bytes", cat.SizeBytes)
	buf := make([]byte, contentChunkSize)
	var sent int64
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := stream.Send(&aegisonev1.ContentChunk{Data: buf[:n]}); err != nil {
				s.log.Warn("fetch content: send failed", "device_id", known.DeviceID, "sent_bytes", sent, "error", err.Error())
				return err
			}
			sent += int64(n)
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			s.log.Error("fetch content: read cab file", "file", cat.FileName, "error", rerr.Error())
			return status.Error(codes.Internal, "content read failed")
		}
	}
	s.log.Info("fetch content: cab sent", "device_id", known.DeviceID, "bytes", sent, "duration", time.Since(start).Round(time.Millisecond).String())
	return nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
