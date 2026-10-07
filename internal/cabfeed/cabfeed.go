// Package cabfeed keeps a current copy of Microsoft's offline scan catalog
// (wsusscn2.cab, ~640 MB) on the server so agents can fetch it from us instead
// of the internet - the agent's offline scan never goes online for detection.
//
// Sync does a conditional GET (If-None-Match on the last ETag), so an unchanged
// cab costs one 304. A new cab is streamed to a temp file while hashing, and is
// only promoted to current if it is complete (byte count == Content-Length) and
// is actually a CAB ("MSCF" header) - otherwise the previous good cab stays
// current (fail closed). Files are named by SHA-256; the current one and the
// previous one are kept (the previous so agents mid-download can finish).
//
// Not done here: verifying Microsoft's Authenticode signature on the cab. The
// download is HTTPS from Microsoft's CDN, but there is no Authenticode verifier
// in the Go stdlib and the server runs on Linux; see the agent spec for the
// endpoint-side story.
package cabfeed

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"aegis-one/internal/feedrun"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	SourceURL = "https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab"
	source    = "microsoft_wsusscn2"
	subdir    = "wsusscn2"
)

var feed = feedrun.Feed{Name: source, Type: "patch_metadata", SourceURL: SourceURL}

type Catalog struct {
	SHA256             string
	SizeBytes          int64
	FileName           string // relative to the content dir
	SourceLastModified *time.Time
	DownloadedAt       time.Time
}

type Result struct {
	Changed bool // a new cab was downloaded and made current
	Catalog *Catalog
}

// Sync checks Microsoft for a newer cab and downloads it if there is one.
func Sync(ctx context.Context, pool *pgxpool.Pool, contentDir string) (Result, error) {
	var res Result
	err := feedrun.Track(ctx, pool, feed, func() (string, int, int, error) {
		// A hard-killed earlier run leaves its partial download behind (defers
		// don't run), up to ~640 MB each; clear those on every run. Safe: only
		// one download runs at a time (the scheduler's per-feed advisory lock +
		// sequential jobs).
		if stale, err := filepath.Glob(filepath.Join(contentDir, subdir, ".download-*.tmp")); err == nil {
			for _, s := range stale {
				os.Remove(s)
			}
		}

		var lastETag string
		var lastModified *time.Time
		var currentSize int64
		err := pool.QueryRow(ctx, `
			SELECT coalesce(source_etag, ''), source_last_modified, size_bytes
			FROM scan_catalogs WHERE source = $1 AND is_current`, source).Scan(&lastETag, &lastModified, &currentSize)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", 0, 0, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, SourceURL, nil)
		if err != nil {
			return "", 0, 0, err
		}
		if lastETag != "" {
			req.Header.Set("If-None-Match", lastETag)
		}
		if lastModified != nil {
			req.Header.Set("If-Modified-Since", lastModified.UTC().Format(http.TimeFormat))
		}
		// No overall client timeout: a 640 MB body can legitimately take many
		// minutes; the caller's ctx bounds the run instead.
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: time.Minute}}
		resp, err := client.Do(req)
		if err != nil {
			return "", 0, 0, fmt.Errorf("cab: request: %w", err)
		}
		defer resp.Body.Close()

		// The second check covers a CDN edge that ignores the conditional
		// headers and answers 200 for the version we already have: the body
		// is not downloaded (closing it aborts the transfer).
		if resp.StatusCode == http.StatusNotModified || sameVersion(resp, lastETag, currentSize) {
			res.Catalog, err = Current(ctx, pool)
			return lastETag, 0, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			return "", 0, 0, fmt.Errorf("cab: %s returned %d", SourceURL, resp.StatusCode)
		}

		cat, err := download(resp, contentDir)
		if err != nil {
			return "", 0, 0, err
		}
		etag := resp.Header.Get("ETag")
		if err := promote(ctx, pool, contentDir, cat, etag); err != nil {
			return "", 0, 0, err
		}
		res.Changed, res.Catalog = true, cat
		return etag, 1, 0, nil
	})
	return res, err
}

// sameVersion reports whether a 200 response is the cab we already have: same
// (non-empty) ETag and same Content-Length.
func sameVersion(resp *http.Response, lastETag string, currentSize int64) bool {
	return resp.StatusCode == http.StatusOK && lastETag != "" &&
		resp.Header.Get("ETag") == lastETag && resp.ContentLength == currentSize
}

func download(resp *http.Response, contentDir string) (*Catalog, error) {
	dir := filepath.Join(contentDir, subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	suffix := make([]byte, 6)
	rand.Read(suffix)
	tmp := filepath.Join(dir, ".download-"+hex.EncodeToString(suffix)+".tmp")
	f, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp) // no-op once renamed

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("cab: download interrupted after %d bytes: %w", n, err)
	}
	if want, perr := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); perr == nil && n != want {
		return nil, fmt.Errorf("cab: incomplete download: got %d of %d bytes", n, want)
	}
	if err := checkCABHeader(tmp); err != nil {
		return nil, err
	}

	sum := hex.EncodeToString(h.Sum(nil))
	// Stored slash-separated so the DB row means the same thing on any OS.
	name := subdir + "/" + sum + ".cab"
	if err := os.Rename(tmp, filepath.Join(contentDir, filepath.FromSlash(name))); err != nil {
		return nil, err
	}
	cat := &Catalog{SHA256: sum, SizeBytes: n, FileName: name, DownloadedAt: time.Now()}
	if lm, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		cat.SourceLastModified = &lm
	}
	return cat, nil
}

// checkCABHeader rejects anything that isn't a Microsoft cabinet file - e.g. a
// captive-portal or proxy error page served with 200.
func checkCABHeader(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil || !bytes.Equal(magic, []byte("MSCF")) {
		return fmt.Errorf("cab: downloaded file is not a CAB (missing MSCF header)")
	}
	return nil
}

// promote makes cat the current catalog and prunes everything older than the
// previous one (rows and files).
func promote(ctx context.Context, pool *pgxpool.Pool, contentDir string, cat *Catalog, etag string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx, `UPDATE scan_catalogs SET is_current = false WHERE source = $1 AND is_current`, source); err != nil {
		return err
	}
	// Same bytes re-published under a new ETag: refresh the existing row.
	if _, err := tx.Exec(ctx, `
		INSERT INTO scan_catalogs (source, sha256_hash, size_bytes, file_name, source_url, source_etag, source_last_modified, is_current)
		VALUES ($1, $2, $3, $4, $5, $6, $7, true)
		ON CONFLICT (sha256_hash) DO UPDATE SET
			is_current = true, source_etag = EXCLUDED.source_etag,
			source_last_modified = EXCLUDED.source_last_modified, downloaded_at = now()`,
		source, cat.SHA256, cat.SizeBytes, cat.FileName, SourceURL, etag, cat.SourceLastModified); err != nil {
		return err
	}

	rows, err := tx.Query(ctx, `
		DELETE FROM scan_catalogs WHERE id IN (
			SELECT id FROM scan_catalogs WHERE source = $1 AND NOT is_current
			ORDER BY downloaded_at DESC OFFSET 1)
		RETURNING file_name`, source)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			rows.Close()
			return err
		}
		stale = append(stale, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	for _, f := range stale {
		os.Remove(filepath.Join(contentDir, filepath.FromSlash(f))) // best-effort; the row is already gone
	}
	return nil
}

// Current returns the catalog agents should download, or nil if none yet.
func Current(ctx context.Context, pool *pgxpool.Pool) (*Catalog, error) {
	var c Catalog
	err := pool.QueryRow(ctx, `
		SELECT sha256_hash, size_bytes, file_name, source_last_modified, downloaded_at
		FROM scan_catalogs WHERE source = $1 AND is_current`, source,
	).Scan(&c.SHA256, &c.SizeBytes, &c.FileName, &c.SourceLastModified, &c.DownloadedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
