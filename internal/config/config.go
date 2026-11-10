// Package config loads the application server's runtime configuration from
// environment variables. Defaults match the dev mTLS layout produced by
// cmd/certgen (./certs) and the agent's own defaults (cmd/agent/internal/config),
// so `go run ./cmd/certgen && go run ./cmd/server` works with no extra setup.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	GRPCAddr string // mTLS AgentControlPlane listen address
	HTTPAddr string // HTTPS API (/internal/*) + /healthz, /readyz listen address

	TLSCAFile   string // CA bundle used to verify agent client certs
	TLSCertFile string // server certificate
	TLSKeyFile  string // server private key

	// HTTPTLS serves the HTTP API over TLS (default). Turn off ONLY behind a
	// TLS-terminating proxy - API bearer tokens are otherwise sent in cleartext.
	HTTPTLS bool
	// The API cert defaults to the agent-facing server cert but can differ, e.g.
	// a cert from the customer's own CA for the API/console.
	HTTPTLSCertFile string
	HTTPTLSKeyFile  string

	// DatabaseURL is optional at this stage (no ingestion wired yet). When unset,
	// /readyz reports ready without a DB check rather than failing startup.
	DatabaseURL string

	// CommandSigningKeyFile holds the Ed25519 private key (base64, as written by
	// cmd/keygen) used to sign commands pushed to agents.
	CommandSigningKeyFile string

	// Enrollment CA (cmd/cagen). Enrollment is enabled only when the CA key file
	// exists and a passphrase is provided (CAKeyPassphrase - kept out of this
	// struct on purpose so it can't end up in a log of the config).
	CACertFile string
	CAKeyFile  string
	// AgentCertTTL is the lifetime of issued agent client certs; the agent renews
	// at ~2/3 of it. 398 days follows the agent team's handoff (BigFix convention).
	AgentCertTTL time.Duration
	// LicenseMaxDevices caps devices that hold a seat (0 = unlimited). Interim:
	// a signed license file (licenses table) isn't verified yet.
	LicenseMaxDevices int

	// AllowPrivilegedDB lets the server start even if its DB login is a superuser
	// or table owner (which can disable audit_log's protections). Local dev ONLY.
	AllowPrivilegedDB bool

	// ContentDir holds content the server redistributes to agents (the ~640 MB
	// scan cab, current + previous version). Needs a persistent volume in Docker.
	ContentDir string
	// ContentMaxStreams caps concurrent agent downloads (FetchContent); further
	// requests wait for a free slot. Bounds server disk/network load when a new
	// cab makes the whole fleet fetch at once.
	ContentMaxStreams int
	// BSDTar is the libarchive CLI used to open the scan cab's LZX-compressed
	// inner cabs (package "libarchive-tools" on Debian/Alpine; tar.exe on
	// Windows 10+).
	BSDTar string
	// PatchDownloadWorkers is how many patch files the server downloads from
	// Microsoft at once when patches are pushed.
	PatchDownloadWorkers int
	// SoftwareMaxUploadBytes caps one software package upload
	// (POST /internal/software/packages).
	SoftwareMaxUploadBytes int64

	// FeedScheduler runs the MSRC/CISA KEV syncs in-process (needs a database and
	// outbound internet). Set AEGIS_FEED_SCHEDULER=off on air-gapped deployments.
	FeedScheduler bool
	// MSRCDocuments is how many of the newest monthly MSRC documents each
	// scheduled sync reads (AEGIS_MSRC_DOCUMENTS, 1..12, default 2): before
	// Patch Tuesday the newest is nearly empty, and the previous month keeps
	// getting revised.
	MSRCDocuments int

	// CabManifest: when false (AEGIS_CAB_MANIFEST=off) agents are not told about
	// the scan cab, so they never download it (~640 MB each). Their optional
	// cab scan, which finds .NET / Office / standalone updates, then stops; the
	// server-side diff still covers cumulative updates.
	CabManifest bool
	// CabAnnounceSpread spreads a NEW cab's announcement to connected agents
	// over this window, in random order, instead of all at once
	// (AEGIS_CAB_ANNOUNCE_SPREAD, e.g. "6h"; default 0 = at once). Agents that
	// connect meanwhile get the manifest straight away.
	CabAnnounceSpread time.Duration

	LogLevel string // debug | info | warn | error

	ShutdownTimeout time.Duration
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func Load() Config {
	tlsCert := getenv("AEGIS_TLS_CERT", "certs/server.crt")
	tlsKey := getenv("AEGIS_TLS_KEY", "certs/server.key")
	tlsCA := getenv("AEGIS_TLS_CA", "certs/ca.crt")
	certTTL, err := time.ParseDuration(getenv("AEGIS_AGENT_CERT_TTL", "9552h")) // 398 days
	if err != nil || certTTL <= 0 {
		certTTL = 9552 * time.Hour
	}
	licenseMax, err := strconv.Atoi(getenv("AEGIS_LICENSE_MAX_DEVICES", "0"))
	if err != nil || licenseMax < 0 {
		licenseMax = 0
	}
	contentStreams, err := strconv.Atoi(getenv("AEGIS_CONTENT_MAX_STREAMS", "50"))
	if err != nil || contentStreams < 1 {
		contentStreams = 50
	}
	downloadWorkers, err := strconv.Atoi(getenv("AEGIS_PATCH_DOWNLOAD_WORKERS", "2"))
	if err != nil || downloadWorkers < 1 {
		downloadWorkers = 2
	}
	maxUpload, err := strconv.ParseInt(getenv("AEGIS_SOFTWARE_MAX_UPLOAD_BYTES", "4294967296"), 10, 64) // 4 GiB
	if err != nil || maxUpload < 1 {
		maxUpload = 4 << 30
	}
	msrcDocs, err := strconv.Atoi(getenv("AEGIS_MSRC_DOCUMENTS", "2"))
	if err != nil || msrcDocs < 1 || msrcDocs > 12 {
		msrcDocs = 2
	}
	cabSpread, err := time.ParseDuration(getenv("AEGIS_CAB_ANNOUNCE_SPREAD", "0"))
	if err != nil || cabSpread < 0 || cabSpread > 7*24*time.Hour {
		cabSpread = 0
	}
	return Config{
		GRPCAddr:               getenv("AEGIS_GRPC_ADDR", ":50051"),
		HTTPAddr:               getenv("AEGIS_HTTP_ADDR", ":8080"),
		TLSCAFile:              tlsCA,
		CACertFile:             getenv("AEGIS_CA_CERT", tlsCA),
		CAKeyFile:              getenv("AEGIS_CA_KEY_FILE", "certs/ca.key.enc"),
		AgentCertTTL:           certTTL,
		LicenseMaxDevices:      licenseMax,
		TLSCertFile:            tlsCert,
		TLSKeyFile:             tlsKey,
		HTTPTLS:                !strings.EqualFold(getenv("AEGIS_HTTP_TLS", "on"), "off"),
		HTTPTLSCertFile:        getenv("AEGIS_HTTP_TLS_CERT", tlsCert),
		HTTPTLSKeyFile:         getenv("AEGIS_HTTP_TLS_KEY", tlsKey),
		DatabaseURL:            getenv("AEGIS_DATABASE_URL", ""),
		CommandSigningKeyFile:  getenv("AEGIS_COMMAND_SIGNING_KEY_FILE", "secrets/command_signing.key"),
		AllowPrivilegedDB:      strings.EqualFold(getenv("AEGIS_ALLOW_PRIVILEGED_DB", "no"), "yes"),
		ContentDir:             getenv("AEGIS_CONTENT_DIR", "content"),
		ContentMaxStreams:      contentStreams,
		BSDTar:                 getenv("AEGIS_BSDTAR", "bsdtar"),
		PatchDownloadWorkers:   downloadWorkers,
		SoftwareMaxUploadBytes: maxUpload,
		FeedScheduler:          !strings.EqualFold(getenv("AEGIS_FEED_SCHEDULER", "on"), "off"),
		MSRCDocuments:          msrcDocs,
		CabManifest:            !strings.EqualFold(getenv("AEGIS_CAB_MANIFEST", "on"), "off"),
		CabAnnounceSpread:      cabSpread,
		LogLevel:               getenv("AEGIS_LOG_LEVEL", "info"),
		ShutdownTimeout:        10 * time.Second,
	}
}

// CAKeyPassphrase returns the enrollment CA key passphrase from
// AEGIS_CA_KEY_PASSPHRASE, or from the file named by AEGIS_CA_KEY_PASSPHRASE_FILE
// (e.g. a Docker/K8s secret mount). "" when neither is set.
func CAKeyPassphrase() (string, error) {
	if v := os.Getenv("AEGIS_CA_KEY_PASSPHRASE"); v != "" {
		return v, nil
	}
	if f := strings.TrimSpace(os.Getenv("AEGIS_CA_KEY_PASSPHRASE_FILE")); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read AEGIS_CA_KEY_PASSPHRASE_FILE: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return "", nil
}
