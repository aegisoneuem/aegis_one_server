// Package config loads the application server's runtime configuration from
// environment variables. Defaults match the dev mTLS layout produced by
// cmd/certgen (./certs) and the agent's own defaults (cmd/agent/internal/config),
// so `go run ./cmd/certgen && go run ./cmd/server` works with no extra setup.
package config

import (
	"os"
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

	// FeedScheduler runs the MSRC/CISA KEV syncs in-process (needs a database and
	// outbound internet). Set AEGIS_FEED_SCHEDULER=off on air-gapped deployments.
	FeedScheduler bool

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
	return Config{
		GRPCAddr:              getenv("AEGIS_GRPC_ADDR", ":50051"),
		HTTPAddr:              getenv("AEGIS_HTTP_ADDR", ":8080"),
		TLSCAFile:             getenv("AEGIS_TLS_CA", "certs/ca.crt"),
		TLSCertFile:           tlsCert,
		TLSKeyFile:            tlsKey,
		HTTPTLS:               !strings.EqualFold(getenv("AEGIS_HTTP_TLS", "on"), "off"),
		HTTPTLSCertFile:       getenv("AEGIS_HTTP_TLS_CERT", tlsCert),
		HTTPTLSKeyFile:        getenv("AEGIS_HTTP_TLS_KEY", tlsKey),
		DatabaseURL:           getenv("AEGIS_DATABASE_URL", ""),
		CommandSigningKeyFile: getenv("AEGIS_COMMAND_SIGNING_KEY_FILE", "secrets/command_signing.key"),
		FeedScheduler:         !strings.EqualFold(getenv("AEGIS_FEED_SCHEDULER", "on"), "off"),
		LogLevel:              getenv("AEGIS_LOG_LEVEL", "info"),
		ShutdownTimeout:       10 * time.Second,
	}
}
