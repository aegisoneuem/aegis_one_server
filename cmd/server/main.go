// cmd/server is the Aegis One application server entrypoint: the gRPC/mTLS
// AgentControlPlane endpoint the agent connects to, plus /healthz and /readyz
// for container orchestration.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"crypto/ed25519"
	"log/slog"

	agentcontrolv1 "aegis-one/gen/agentcontrol/v1"
	"aegis-one/internal/apiauth"
	"aegis-one/internal/cabfeed"
	"aegis-one/internal/commands"
	"aegis-one/internal/complianceapi"
	"aegis-one/internal/config"
	"aegis-one/internal/contentapi"
	"aegis-one/internal/crypto"
	"aegis-one/internal/db"
	"aegis-one/internal/feedsched"
	"aegis-one/internal/grpcserver"
	"aegis-one/internal/identity"
	"aegis-one/internal/ingest"
	"aegis-one/internal/kev"
	"aegis-one/internal/logging"
	"aegis-one/internal/patchfeed"
	"aegis-one/internal/pushapi"
	"aegis-one/internal/signing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

func main() {
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var pool *pgxpool.Pool
	if cfg.DatabaseURL != "" {
		p, err := db.New(ctx, cfg.DatabaseURL)
		if err != nil {
			log.Error("database connection failed", "error", err.Error())
			os.Exit(1)
		}
		pool = p
		defer pool.Close()
		log.Info("database connected")

		rep, err := db.CheckPrivileges(ctx, pool)
		if err != nil {
			log.Error("database privilege check failed", "error", err.Error())
			os.Exit(1)
		}
		for _, w := range rep.Warnings {
			log.Warn("database login "+w, "db_user", rep.User)
		}
		if len(rep.Fatal) > 0 {
			problems := strings.Join(rep.Fatal, "; ")
			if !cfg.AllowPrivilegedDB {
				log.Error("refusing to start: database login can bypass audit_log protections - connect as a login in the aegis_app role (AEGIS_ALLOW_PRIVILEGED_DB=yes overrides, local dev only)",
					"db_user", rep.User, "problems", problems)
				os.Exit(1)
			}
			log.Warn("INSECURE: running with a privileged database login (AEGIS_ALLOW_PRIVILEGED_DB=yes) - never do this outside local dev",
				"db_user", rep.User, "problems", problems)
		}
	} else {
		log.Warn("AEGIS_DATABASE_URL not set; /readyz will not check the database")
	}

	creds, err := crypto.ServerCredentials(cfg.TLSCAFile, cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		log.Error("mTLS setup failed (run cmd/certgen first?)", "error", err.Error())
		os.Exit(1)
	}

	grpcSrv := grpc.NewServer(
		grpc.Creds(creds),
		// The agent pings on its own keepalive timer (default 60s); without a
		// permissive enforcement policy the server would GOAWAY it as abusive.
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             20 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if pool == nil {
		log.Warn("identity tracking disabled (no database); trusting agent-reported device_id as-is")
	}
	var cmdStore *commands.Store
	if pool != nil {
		cmdStore = commands.New(pool)
	}
	agentSrv := grpcserver.New(log, identity.New(pool), ingest.New(pool), cmdStore)
	agentcontrolv1.RegisterAgentControlPlaneServer(grpcSrv, agentSrv)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Error("grpc listen failed", "addr", cfg.GRPCAddr, "error", err.Error())
		os.Exit(1)
	}

	var signingKey ed25519.PrivateKey
	var signingKeyID string
	if key, err := signing.LoadPrivateKey(cfg.CommandSigningKeyFile); err != nil {
		log.Warn("command signing key not loaded; push API will 503", "error", err.Error())
	} else {
		signingKey = key
		log.Info("command signing key loaded", "file", cfg.CommandSigningKeyFile)
		if cmdStore != nil {
			id, err := cmdStore.ResolveSigningKey(ctx, key, cfg.CommandSigningKeyFile)
			if err != nil {
				log.Error("could not resolve signing key in signing_keys", "error", err.Error())
				os.Exit(1)
			}
			signingKeyID = id
			log.Info("command signing key registered", "signing_key_id", id)
		}
	}

	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpMux(pool, agentSrv, cmdStore, signingKey, signingKeyID, cfg.ContentDir, log),
		ReadHeaderTimeout: 10 * time.Second,
		// net/http logs TLS handshake errors etc. through the std logger; route
		// them through slog so every server log line stays structured JSON.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if cfg.HTTPTLS {
		tlsCfg, err := crypto.HTTPServerTLSConfig(cfg.HTTPTLSCertFile, cfg.HTTPTLSKeyFile, cfg.TLSCAFile)
		if err != nil {
			log.Error("HTTPS setup failed (set AEGIS_HTTP_TLS_CERT/KEY, or AEGIS_HTTP_TLS=off only behind a TLS proxy)", "error", err.Error())
			os.Exit(1)
		}
		httpSrv.TLSConfig = tlsCfg
	} else {
		log.Warn("HTTP API is plain HTTP (AEGIS_HTTP_TLS=off): API tokens travel in cleartext unless a TLS-terminating proxy is in front")
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		log.Info("grpc server listening", "addr", cfg.GRPCAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			log.Error("grpc server stopped", "error", err.Error())
		}
	}()

	go func() {
		defer wg.Done()
		var err error
		if cfg.HTTPTLS {
			log.Info("https server listening", "addr", cfg.HTTPAddr, "cert", cfg.HTTPTLSCertFile)
			err = httpSrv.ListenAndServeTLS("", "") // cert already in TLSConfig
		} else {
			log.Info("http server listening", "addr", cfg.HTTPAddr)
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server stopped", "error", err.Error())
		}
	}()

	switch {
	case pool == nil:
		log.Warn("feed scheduler disabled (no database)")
	case !cfg.FeedScheduler:
		log.Info("feed scheduler disabled (AEGIS_FEED_SCHEDULER=off)")
	default:
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("feed scheduler started", "check_every", feedsched.CheckEvery.String())
			feedsched.New(pool, log, feedJobs(cfg.ContentDir)...).Run(ctx)
		}()
	}

	<-ctx.Done()
	log.Info("shutdown signal received, draining")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("http shutdown error", "error", err.Error())
	}
	grpcSrv.GracefulStop()

	wg.Wait()
	log.Info("shutdown complete")
}

// feedJobs lists the scheduled feeds. Names must match the content_feeds.name
// each sync records under. MSRC runs first, but either order converges
// (both call kev.Apply).
func feedJobs(contentDir string) []feedsched.Job {
	return []feedsched.Job{
		{Name: "microsoft_cvrf", Run: func(ctx context.Context, pool *pgxpool.Pool) (string, error) {
			s, err := patchfeed.RunLatest(ctx, pool)
			return fmt.Sprintf("%s: %d KBs, %d CVEs, %d has_kev changed, %d deadlines tightened",
				s.DocumentID, s.KBsSeen, s.CVEsSeen, s.KEVPatchesChanged, s.DeadlinesTightened), err
		}},
		{Name: "cisa_kev", Run: func(ctx context.Context, pool *pgxpool.Pool) (string, error) {
			s, err := kev.Run(ctx, pool)
			return fmt.Sprintf("catalog %s: %d entries, %d CVE added, %d flagged, %d un-flagged, %d has_kev changed, %d deadlines tightened",
				s.CatalogVersion, s.Entries, s.CVEsAdded, s.CVEsFlagged, s.CVEsUnflagged, s.PatchesChanged, s.DeadlinesTightened), err
		}},
		// ~640 MB; a conditional GET makes the daily check a 304 when unchanged,
		// but a real download needs far more than the default run timeout.
		{Name: "microsoft_wsusscn2", Timeout: time.Hour, Run: func(ctx context.Context, pool *pgxpool.Pool) (string, error) {
			res, err := cabfeed.Sync(ctx, pool, contentDir)
			if err != nil || res.Catalog == nil {
				return "no catalog", err
			}
			state := "unchanged"
			if res.Changed {
				state = "downloaded"
			}
			return fmt.Sprintf("%s, sha256 %s, %d bytes", state, res.Catalog.SHA256, res.Catalog.SizeBytes), nil
		}},
	}
}

func httpMux(pool *pgxpool.Pool, agentSrv *grpcserver.Server, cmdStore *commands.Store, signingKey ed25519.PrivateKey, signingKeyID string, contentDir string, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if pool != nil {
			if err := pool.Ping(r.Context()); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("database unreachable: " + err.Error()))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})
	// /healthz and /readyz stay open for orchestrator probes; everything under
	// /internal requires an API token. Push checks its permission itself (it
	// depends on the command type).
	auth := apiauth.New(pool, log)
	mux.Handle("/internal/push", auth.Require("", pushapi.New(agentSrv, cmdStore, signingKey, signingKeyID, log)))
	mux.Handle("/internal/compliance", auth.Require(apiauth.PermReportsView, complianceapi.New(pool)))
	// /content/* authorizes per request: agent mTLS cert or a content.download token.
	mux.Handle("/content/", contentapi.New(pool, contentDir, identity.New(pool), auth, log))
	return mux
}
