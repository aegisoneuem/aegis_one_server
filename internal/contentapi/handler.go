// Package contentapi serves redistributable content to agents over the HTTPS
// listener - today the offline scan catalog (wsusscn2.cab).
//
//	GET /content/wsusscn2.json  -> {sha256, size_bytes, ...} of the current cab
//	GET /content/wsusscn2.cab   -> the cab (Range/resume and If-Range supported)
//
// Callers: an agent presenting its mTLS client certificate (the same one it
// uses on gRPC; must be a known, non-revoked agent), or IT tooling with an API
// token holding content.download. The cab is public Microsoft content, but the
// endpoint is still gated so it can't be used as an open 640 MB download.
package contentapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"aegis-one/internal/apiauth"
	"aegis-one/internal/cabfeed"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Handler struct {
	pool       *pgxpool.Pool
	contentDir string
	idr        *identity.Resolver
	auth       *apiauth.Authenticator
	log        *slog.Logger
}

func New(pool *pgxpool.Pool, contentDir string, idr *identity.Resolver, auth *apiauth.Authenticator, log *slog.Logger) *Handler {
	return &Handler{pool: pool, contentDir: contentDir, idr: idr, auth: auth, log: log}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if h.pool == nil {
		http.Error(w, "database required", http.StatusServiceUnavailable)
		return
	}
	who, status := h.caller(r)
	if status != http.StatusOK {
		http.Error(w, http.StatusText(status), status)
		return
	}

	cat, err := cabfeed.Current(r.Context(), h.pool)
	if err != nil {
		h.log.Error("content: look up current cab", "error", err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if cat == nil {
		http.Error(w, "no scan catalog downloaded yet", http.StatusNotFound)
		return
	}

	switch r.URL.Path {
	case "/content/wsusscn2.json":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"sha256":               cat.SHA256,
			"size_bytes":           cat.SizeBytes,
			"source_last_modified": cat.SourceLastModified,
			"downloaded_at":        cat.DownloadedAt,
			"url":                  "/content/wsusscn2.cab",
		})

	case "/content/wsusscn2.cab":
		f, err := os.Open(filepath.Join(h.contentDir, filepath.FromSlash(cat.FileName)))
		if err != nil {
			h.log.Error("content: current cab file missing on disk", "file", cat.FileName, "error", err.Error())
			http.Error(w, "scan catalog unavailable", http.StatusServiceUnavailable)
			return
		}
		defer f.Close()
		// ETag = content hash, so an agent resuming with If-Range gets the whole
		// new file (not a spliced one) if the cab changed mid-download.
		w.Header().Set("ETag", `"`+cat.SHA256+`"`)
		w.Header().Set("X-Content-SHA256", cat.SHA256)
		w.Header().Set("Content-Type", "application/vnd.ms-cab-compressed")
		if r.Header.Get("Range") == "" {
			h.log.Info("content: serving scan catalog", "caller", who, "sha256", cat.SHA256[:12])
		}
		http.ServeContent(w, r, "wsusscn2.cab", cat.DownloadedAt, f)

	default:
		http.NotFound(w, r)
	}
}

// caller authorizes r and returns a label for logs, or the HTTP status to fail
// with: 401 no usable credential, 403 known credential without access.
func (h *Handler) caller(r *http.Request) (string, int) {
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		known, err := h.idr.Lookup(r.Context(), identity.Fingerprint(r.TLS.PeerCertificates[0]))
		if err != nil {
			h.log.Error("content: agent lookup failed", "error", err.Error())
			return "", http.StatusServiceUnavailable
		}
		if known == nil || known.Revoked {
			h.log.Warn("content: rejected agent certificate (unknown or revoked)", "remote", r.RemoteAddr)
			return "", http.StatusForbidden
		}
		return "agent:" + known.DeviceID, http.StatusOK
	}

	p, err := h.auth.Authenticate(r)
	if err != nil {
		return "", http.StatusUnauthorized
	}
	if !p.Can(apiauth.PermContentDownload) {
		h.log.Warn("content: token lacks content.download", "client", p.ClientName)
		return "", http.StatusForbidden
	}
	return "client:" + p.ClientName, http.StatusOK
}
