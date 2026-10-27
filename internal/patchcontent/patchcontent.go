// Package patchcontent downloads Windows update files to the server when a
// patch is pushed, so agents can fetch them over FetchContent (kind "patch")
// without touching the internet.
//
// Requests come from the push flow as wucatalog files (URL + Microsoft's SHA-1).
// A worker pool claims pending rows from patch_content, downloads each file
// from an allowlisted Microsoft host (redirects included), and accepts it only
// if its SHA-1 matches the catalog digest. The file is then stored as
// patches/<sha256><ext>; SHA-256 is what agents verify (InstallPatchSpec
// expected_hash). Failed downloads retry with backoff, then stay 'failed' until
// requested again.
//
// The catalog's SHA-1 comes from the wsusscn2.cab, downloaded over HTTPS from
// Microsoft; its Authenticode signature is not verified here (see cabfeed).
// DISM verifies the .msu's own Microsoft signature at install time.
package patchcontent

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aegis-one/internal/wucatalog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	subdir      = "patches"
	maxAttempts = 5
	// maxFileBytes bounds a single download; current cumulative .msu files are
	// a few GB.
	maxFileBytes = 16 << 30
)

// allowedHosts are the Microsoft download hosts wsusscn2.cab points at.
var allowedHosts = []string{
	"download.windowsupdate.com",
	".download.windowsupdate.com",
	"dl.delivery.mp.microsoft.com",
	".dl.delivery.mp.microsoft.com",
	"download.microsoft.com",
}

func hostAllowed(u *url.URL) bool {
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, a := range allowedHosts {
		if strings.HasPrefix(a, ".") && strings.HasSuffix(h, a) || h == a {
			return true
		}
	}
	return false
}

// Content is a downloaded file, ready to serve.
type Content struct {
	Digest     string
	FileName   string
	SHA256     string
	SizeBytes  int64
	StoredName string // relative to the content dir
}

type Store struct {
	pool *pgxpool.Pool
	dir  string
	log  *slog.Logger
	http *http.Client
	wake chan struct{}
}

func New(pool *pgxpool.Pool, contentDir string, log *slog.Logger) *Store {
	s := &Store{pool: pool, dir: contentDir, log: log, wake: make(chan struct{}, 1)}
	s.http = &http.Client{
		// No overall timeout: a multi-GB file can legitimately take long. Stalls
		// are caught by the transport's header timeout and the context.
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ResponseHeaderTimeout: time.Minute,
			IdleConnTimeout:       90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !hostAllowed(req.URL) {
				return fmt.Errorf("redirect to non-Microsoft host %q refused", req.URL.Host)
			}
			return nil
		},
	}
	return s
}

// Request queues files for download. Files already pending/ready are left
// alone; a previously failed file is retried. It returns how many files are
// not ready yet.
func (s *Store) Request(ctx context.Context, files []wucatalog.File) (notReady int, err error) {
	for _, f := range files {
		u, err := url.Parse(f.URL)
		if err != nil || !hostAllowed(u) {
			return 0, fmt.Errorf("file %s: download URL %q is not an allowed Microsoft host", f.Name, f.URL)
		}
		var state string
		err = s.pool.QueryRow(ctx, `
			INSERT INTO patch_content (file_digest, file_name, url)
			VALUES ($1, $2, $3)
			ON CONFLICT (file_digest) DO UPDATE SET
				state = CASE WHEN patch_content.state = 'failed' THEN 'pending' ELSE patch_content.state END,
				attempts = CASE WHEN patch_content.state = 'failed' THEN 0 ELSE patch_content.attempts END,
				next_attempt_at = CASE WHEN patch_content.state = 'failed' THEN now() ELSE patch_content.next_attempt_at END,
				url = EXCLUDED.url
			RETURNING state`, f.Digest, f.Name, f.URL).Scan(&state)
		if err != nil {
			return 0, fmt.Errorf("queue %s: %w", f.Name, err)
		}
		if state != "ready" {
			notReady++
		}
	}
	if notReady > 0 {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	return notReady, nil
}

// States returns digest -> state for the given digests.
func (s *Store) States(ctx context.Context, digests []string) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT file_digest, state FROM patch_content WHERE file_digest = ANY($1)`, digests)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var d, st string
		if err := rows.Scan(&d, &st); err != nil {
			return nil, err
		}
		out[d] = st
	}
	return out, rows.Err()
}

// ByDigest returns a ready file, or nil.
func (s *Store) ByDigest(ctx context.Context, digest string) (*Content, error) {
	return s.ready(ctx, `file_digest = $1`, digest)
}

// BySHA256 returns a ready file, or nil.
func (s *Store) BySHA256(ctx context.Context, sha256Hex string) (*Content, error) {
	return s.ready(ctx, `sha256_hash = $1`, strings.ToLower(sha256Hex))
}

func (s *Store) ready(ctx context.Context, where string, arg any) (*Content, error) {
	var c Content
	err := s.pool.QueryRow(ctx, `
		SELECT file_digest, file_name, sha256_hash, size_bytes, stored_name
		FROM patch_content WHERE state = 'ready' AND `+where, arg,
	).Scan(&c.Digest, &c.FileName, &c.SHA256, &c.SizeBytes, &c.StoredName)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Path is where c lives on disk.
func (s *Store) Path(c *Content) string {
	return filepath.Join(s.dir, filepath.FromSlash(c.StoredName))
}

// Run downloads queued files with `workers` concurrent downloads until ctx ends.
func (s *Store) Run(ctx context.Context, workers int) {
	// A row left 'downloading' was interrupted by a restart.
	if _, err := s.pool.Exec(ctx, `UPDATE patch_content SET state = 'pending', next_attempt_at = now() WHERE state = 'downloading'`); err != nil && ctx.Err() == nil {
		s.log.Warn("patch content: reset interrupted downloads", "error", err.Error())
	}
	if err := os.MkdirAll(filepath.Join(s.dir, subdir), 0o750); err != nil {
		s.log.Error("patch content: create content dir", "error", err.Error())
		return
	}
	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			s.worker(ctx)
		}()
	}
	for i := 0; i < workers; i++ {
		<-done
	}
}

func (s *Store) worker(ctx context.Context) {
	idle := time.NewTicker(15 * time.Second)
	defer idle.Stop()
	for ctx.Err() == nil {
		job, err := s.claim(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("patch content: claim job", "error", err.Error())
			}
		}
		if job == nil {
			select {
			case <-ctx.Done():
			case <-idle.C:
			case <-s.wake:
			}
			continue
		}
		s.process(ctx, job)
	}
}

type job struct {
	digest, name, url string
	attempts          int
}

func (s *Store) claim(ctx context.Context) (*job, error) {
	var j job
	err := s.pool.QueryRow(ctx, `
		UPDATE patch_content SET state = 'downloading', attempts = attempts + 1
		WHERE file_digest = (
			SELECT file_digest FROM patch_content
			WHERE state = 'pending' AND next_attempt_at <= now()
			ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING file_digest, file_name, url, attempts`).Scan(&j.digest, &j.name, &j.url, &j.attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

func (s *Store) process(ctx context.Context, j *job) {
	start := time.Now()
	s.log.Info("patch content: downloading", "file", j.name, "attempt", j.attempts)
	c, err := s.download(ctx, j)
	if err != nil {
		if ctx.Err() != nil {
			return // shutting down; Run's reset re-queues it next start
		}
		state, next := "pending", backoff(j.attempts)
		if j.attempts >= maxAttempts {
			state = "failed"
		}
		if _, uerr := s.pool.Exec(ctx, `
			UPDATE patch_content SET state = $2, last_error = $3, next_attempt_at = now() + $4::interval
			WHERE file_digest = $1`, j.digest, state, err.Error(), fmt.Sprintf("%d seconds", int(next.Seconds()))); uerr != nil {
			s.log.Error("patch content: record failure", "file", j.name, "error", uerr.Error())
		}
		s.log.Warn("patch content: download failed", "file", j.name, "attempt", j.attempts, "state", state, "error", err.Error())
		return
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE patch_content SET state = 'ready', sha256_hash = $2, size_bytes = $3, stored_name = $4,
			last_error = NULL, ready_at = now()
		WHERE file_digest = $1`, j.digest, c.SHA256, c.SizeBytes, c.StoredName); err != nil {
		s.log.Error("patch content: record ready", "file", j.name, "error", err.Error())
		return
	}
	s.log.Info("patch content: ready", "file", j.name, "sha256", c.SHA256, "size_bytes", c.SizeBytes,
		"duration", time.Since(start).Round(time.Second).String())
}

func backoff(attempt int) time.Duration {
	steps := []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}
	if attempt-1 < len(steps) {
		return steps[attempt-1]
	}
	return steps[len(steps)-1]
}

func (s *Store) download(ctx context.Context, j *job) (*Content, error) {
	u, err := url.Parse(j.url)
	if err != nil || !hostAllowed(u) {
		return nil, fmt.Errorf("download URL %q is not an allowed Microsoft host", j.url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u.Host, resp.Status)
	}
	if resp.ContentLength > maxFileBytes {
		return nil, fmt.Errorf("file too large (%d bytes)", resp.ContentLength)
	}

	tmp, err := os.CreateTemp(filepath.Join(s.dir, subdir), ".download-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	h1, h256 := sha1.New(), sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h1, h256), io.LimitReader(resp.Body, maxFileBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("download interrupted after %d bytes: %w", n, err)
	}
	if n > maxFileBytes {
		return nil, fmt.Errorf("file too large (over %d bytes)", int64(maxFileBytes))
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return nil, fmt.Errorf("short download: %d of %d bytes", n, resp.ContentLength)
	}
	if got := base64.StdEncoding.EncodeToString(h1.Sum(nil)); got != j.digest {
		return nil, fmt.Errorf("SHA-1 mismatch: catalog %s, downloaded %s", j.digest, got)
	}

	sum := hex.EncodeToString(h256.Sum(nil))
	stored := subdir + "/" + sum + strings.ToLower(filepath.Ext(j.name))
	if err := os.Rename(tmp.Name(), filepath.Join(s.dir, filepath.FromSlash(stored))); err != nil {
		return nil, err
	}
	return &Content{Digest: j.digest, FileName: j.name, SHA256: sum, SizeBytes: n, StoredName: stored}, nil
}
