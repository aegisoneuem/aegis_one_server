// cmd/server is the Aegis One application server entrypoint: the gRPC/mTLS
// AgentControlPlane endpoint the agent connects to, plus /healthz and /readyz
// for container orchestration.
package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"crypto/ed25519"
	"log/slog"

	agentcontrolv1 "aegis-one/gen/agentcontrol/v1"
	"aegis-one/internal/complianceapi"
	"aegis-one/internal/config"
	"aegis-one/internal/crypto"
	"aegis-one/internal/db"
	"aegis-one/internal/grpcserver"
	"aegis-one/internal/identity"
	"aegis-one/internal/ingest"
	"aegis-one/internal/logging"
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
	agentSrv := grpcserver.New(log, identity.New(pool), ingest.New(pool))
	agentcontrolv1.RegisterAgentControlPlaneServer(grpcSrv, agentSrv)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Error("grpc listen failed", "addr", cfg.GRPCAddr, "error", err.Error())
		os.Exit(1)
	}

	var signingKey ed25519.PrivateKey
	if key, err := signing.LoadPrivateKey(cfg.CommandSigningKeyFile); err != nil {
		log.Warn("command signing key not loaded; push API will 503", "error", err.Error())
	} else {
		signingKey = key
		log.Info("command signing key loaded", "file", cfg.CommandSigningKeyFile)
	}

	httpSrv := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: httpMux(pool, agentSrv, signingKey, log),
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
		log.Info("http server listening", "addr", cfg.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server stopped", "error", err.Error())
		}
	}()

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

func httpMux(pool *pgxpool.Pool, agentSrv *grpcserver.Server, signingKey ed25519.PrivateKey, log *slog.Logger) http.Handler {
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
	mux.Handle("/internal/push", pushapi.New(agentSrv, signingKey, log))
	mux.Handle("/internal/compliance", complianceapi.New(pool))
	return mux
}
