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

	schema "aegis-one/db"
	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/agentactions"
	"aegis-one/internal/agentpolicy"
	"aegis-one/internal/apiauth"
	"aegis-one/internal/ca"
	"aegis-one/internal/cabfeed"
	"aegis-one/internal/commands"
	"aegis-one/internal/complianceapi"
	"aegis-one/internal/config"
	"aegis-one/internal/contentapi"
	"aegis-one/internal/crypto"
	"aegis-one/internal/db"
	"aegis-one/internal/dbmigrate"
	"aegis-one/internal/devices"
	"aegis-one/internal/enroll"
	"aegis-one/internal/feedsched"
	"aegis-one/internal/grpcserver"
	"aegis-one/internal/identity"
	"aegis-one/internal/ingest"
	"aegis-one/internal/kev"
	"aegis-one/internal/logging"
	"aegis-one/internal/patchcontent"
	"aegis-one/internal/patchdeploy"
	"aegis-one/internal/patchdiff"
	"aegis-one/internal/patchfeed"
	"aegis-one/internal/pushapi"
	"aegis-one/internal/remoteops"
	"aegis-one/internal/signing"
	"aegis-one/internal/softwaredist"
	"aegis-one/internal/wucatalog"

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

		// Refuse to run this build against a schema that is behind it.
		migrations, err := dbmigrate.Load(schema.Migrations)
		if err == nil {
			err = dbmigrate.CheckCurrent(ctx, pool, migrations)
		}
		if err != nil {
			log.Error("database schema is not current", "error", err.Error())
			os.Exit(1)
		}

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

	requireCertUnary, requireCertStream := grpcserver.RequireClientCert()
	grpcSrv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(requireCertUnary),
		grpc.ChainStreamInterceptor(requireCertStream),
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
	enrollSvc, err := setupEnrollment(cfg, pool, log)
	if err != nil {
		log.Error("enrollment setup failed", "error", err.Error())
		os.Exit(1)
	}
	agentSrv := grpcserver.New(log, identity.New(pool), ingest.New(pool), cmdStore, enrollSvc)
	if enrollSvc != nil {
		enrollSvc.SetLive(agentSrv) // a strong identity match on a connected device is a conflict, not a reactivation
	}
	var patches *patchcontent.Store
	var software *softwaredist.Store
	var differ *patchdiff.Differ
	var dexWriter *ingest.DexWriter
	if pool != nil {
		dexWriter = ingest.NewDexWriter(pool, log)
		agentSrv.EnableDex(dexWriter)
		patches = patchcontent.New(pool, cfg.ContentDir, log)
		software = softwaredist.NewStore(pool, cfg.ContentDir, cfg.SoftwareMaxUploadBytes, log)
		agentSrv.EnableContent(pool, cfg.ContentDir, cfg.ContentMaxStreams, patches)
		agentSrv.SetCabAnnounce(cfg.CabManifest, cfg.CabAnnounceSpread)
		agentSrv.EnableSoftwareContent(software)
		agentSrv.EnableBaseline(pool)
		differ = patchdiff.New(pool, log)
		agentSrv.EnablePatchDiff(differ)
	} else {
		log.Warn("content delivery to agents disabled (no database)")
	}
	aegisonev1.RegisterAgentControlPlaneServer(grpcSrv, agentSrv)

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

	// Patch push (download -> stage -> install) needs the DB, the content
	// store and a registered signing key.
	var deployer *patchdeploy.Deployer
	if patches != nil && cmdStore != nil && signingKeyID != "" {
		deployer = patchdeploy.New(pool, patches, cmdStore, agentSrv, signingKey, signingKeyID, log)
	} else {
		log.Warn("patch deployment disabled (needs a database and a command signing key)")
	}
	var swDeployer *softwaredist.Deployer
	if software != nil && cmdStore != nil && signingKeyID != "" {
		swDeployer = softwaredist.NewDeployer(pool, software, cmdStore, agentSrv, signingKey, signingKeyID, log)
	}
	// Remote operations (collect_file, run_command, file_operation, transfers,
	// shells) share one sender: signed, recorded, online devices only.
	var remote *remoteOps
	var policyAPI http.Handler
	if pool != nil && cmdStore != nil && signingKeyID != "" {
		sender := &commands.Sender{Store: cmdStore, Disp: agentSrv, Key: signingKey, KeyID: signingKeyID}
		uploads := remoteops.NewUploads(pool, cfg.ContentDir, log)
		remote = &remoteOps{sender: sender, uploads: uploads,
			transfers: remoteops.NewTransfers(pool, uploads, sender, log),
			shells:    remoteops.NewShells(pool, cfg.ContentDir, sender, log)}
		agentSrv.EnableRemoteOps(remote.uploads, remote.transfers, remote.shells)

		// Fleet-wide signed agent policy: pushed on connect, on publish, and
		// again when an agent reports its stored policy tampered with.
		policyStore := agentpolicy.NewStore(pool)
		pusher := agentpolicy.NewPusher(ctx, pool, policyStore, sender, agentSrv, log)
		agentSrv.EnablePolicy(pusher)
		policyAPI = agentpolicy.NewHandler(policyStore, pusher, log)
	} else {
		log.Warn("software deployment disabled (needs a database and a command signing key)")
	}

	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpMux(pool, agentSrv, cmdStore, signingKey, signingKeyID, deployer, software, swDeployer, remote, policyAPI, cfg.ContentDir, log),
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

	// The DEX writer outlives ctx: it must keep draining until the gRPC server
	// has stopped, so it gets its own context, cancelled after GracefulStop.
	dexCtx, stopDex := context.WithCancel(context.Background())
	dexDone := make(chan struct{})
	if dexWriter != nil {
		go func() {
			defer close(dexDone)
			dexWriter.Run(dexCtx)
		}()
	} else {
		close(dexDone)
	}

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

	if pool != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			agentSrv.WatchCab(ctx, time.Minute)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			agentSrv.WatchBaseline(ctx, time.Minute)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			differ.Watch(ctx, time.Minute)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			patches.Run(ctx, cfg.PatchDownloadWorkers)
		}()
	}
	if deployer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deployer.Run(ctx)
		}()
	}
	if remote != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			remote.transfers.Run(ctx)
		}()
		go func() {
			defer wg.Done()
			remote.shells.Run(ctx)
		}()
	}
	if swDeployer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			swDeployer.Run(ctx)
		}()
	}

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
			feedsched.New(pool, log, feedJobs(cfg.ContentDir, cfg.BSDTar, cfg.MSRCDocuments)...).Run(ctx)
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
	stopDex()
	<-dexDone
	if dexWriter != nil {
		written, dropped := dexWriter.Stats()
		log.Info("dex writer drained", "rows_written", written, "rows_dropped", dropped)
	}

	wg.Wait()
	log.Info("shutdown complete")
}

// feedJobs lists the scheduled feeds. Names must match the content_feeds.name
// each sync records under. MSRC runs first, but either order converges
// (both call kev.Apply).
func feedJobs(contentDir, bsdtar string, msrcDocuments int) []feedsched.Job {
	return []feedsched.Job{
		{Name: "microsoft_cvrf", Run: func(ctx context.Context, pool *pgxpool.Pool) (string, error) {
			s, err := patchfeed.RunRecent(ctx, pool, msrcDocuments)
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
			// Map updates to their download URLs (no-op if this cab is already
			// indexed, so an earlier failed index is retried on the next run).
			idx, err := wucatalog.IndexCurrent(ctx, pool, contentDir, bsdtar)
			if err != nil {
				return fmt.Sprintf("%s, sha256 %s; index failed", state, res.Catalog.SHA256), fmt.Errorf("index scan cab: %w", err)
			}
			indexState := "already indexed"
			if !idx.Skipped {
				indexState = fmt.Sprintf("indexed %d updates / %d files", idx.Updates, idx.Rows)
			}
			return fmt.Sprintf("%s, sha256 %s, %d bytes, %s", state, res.Catalog.SHA256, res.Catalog.SizeBytes, indexState), nil
		}},
	}
}

func httpMux(pool *pgxpool.Pool, agentSrv *grpcserver.Server, cmdStore *commands.Store, signingKey ed25519.PrivateKey, signingKeyID string, deployer *patchdeploy.Deployer,
	software *softwaredist.Store, swDeployer *softwaredist.Deployer, remote *remoteOps, policyAPI http.Handler, contentDir string, log *slog.Logger) http.Handler {
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
	if deployer != nil {
		mux.Handle("/internal/deploy", auth.Require(apiauth.PermPatchDeploy, patchdeploy.NewHandler(deployer, log)))
	}
	if software != nil {
		mux.Handle("/internal/software/packages", auth.Require(apiauth.PermSoftwareDeploy, softwaredist.NewPackagesHandler(software, log)))
	}
	if swDeployer != nil {
		mux.Handle("/internal/software/deploy", auth.Require(apiauth.PermSoftwareDeploy, softwaredist.NewDeployHandler(swDeployer, log)))
	}
	if remote != nil {
		// Each of these checks its own permission per action / route.
		mux.Handle("/internal/actions", auth.Require("", agentactions.New(pool, remote.sender, log)))
		mux.Handle("/internal/remote/", auth.Require("", remoteops.NewHandler(pool, remote.sender, remote.uploads, remote.transfers, remote.shells, log)))
	}
	if policyAPI != nil {
		// GET needs devices.view, PUT agent.policy.
		ph := auth.Require("", policyAPI)
		mux.Handle("/internal/policy", ph)
		mux.Handle("/internal/policy/", ph)
	}
	mux.Handle("/internal/compliance", auth.Require(apiauth.PermReportsView, complianceapi.New(pool)))
	if pool != nil {
		// Checks devices.view / devices.manage per route.
		dh := auth.Require("", devices.New(pool, agentSrv, log))
		mux.Handle("/internal/devices", dh)
		mux.Handle("/internal/devices/", dh)
	}
	// /content/* authorizes per request: agent mTLS cert or a content.download token.
	mux.Handle("/content/", contentapi.New(pool, contentDir, identity.New(pool), auth, log))
	return mux
}

// setupEnrollment loads the enrollment CA if one is provisioned (cmd/cagen).
// No CA key file -> enrollment off (dev / pre-provisioned certs; TOFU stays on).
// A CA key file WITHOUT a working passphrase is a misconfiguration and stops the
// server rather than silently running with enrollment disabled.
func setupEnrollment(cfg config.Config, pool *pgxpool.Pool, log *slog.Logger) (*enroll.Service, error) {
	if _, err := os.Stat(cfg.CAKeyFile); err != nil {
		log.Warn("enrollment disabled: no enrollment CA key (run cmd/cagen); unknown agent certs fall back to trust-on-first-use",
			"ca_key_file", cfg.CAKeyFile)
		return nil, nil
	}
	if pool == nil {
		log.Warn("enrollment disabled: needs a database")
		return nil, nil
	}
	passphrase, err := config.CAKeyPassphrase()
	if err != nil {
		return nil, err
	}
	if passphrase == "" {
		return nil, fmt.Errorf("%s exists but AEGIS_CA_KEY_PASSPHRASE / AEGIS_CA_KEY_PASSPHRASE_FILE is not set", cfg.CAKeyFile)
	}
	authority, err := ca.Load(cfg.CACertFile, cfg.CAKeyFile, passphrase)
	if err != nil {
		return nil, err
	}
	log.Info("enrollment enabled", "ca", authority.Cert.Subject.CommonName, "ca_not_after", authority.Cert.NotAfter,
		"agent_cert_ttl", cfg.AgentCertTTL.String(), "license_max_devices", cfg.LicenseMaxDevices)
	return enroll.New(pool, authority, cfg.AgentCertTTL, cfg.LicenseMaxDevices, log), nil
}

// remoteOps groups the remote-operation services shared by the gRPC and HTTP sides.
type remoteOps struct {
	sender    *commands.Sender
	uploads   *remoteops.Uploads
	transfers *remoteops.Transfers
	shells    *remoteops.Shells
}
