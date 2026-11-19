package main

import (
	"context"
	"log/slog"
	"net/http"
)

// dbPinger is what /readyz needs from the database pool.
type dbPinger interface {
	Ping(ctx context.Context) error
}

// readyzHandler answers the unauthenticated readiness probe. On a database
// failure the body is a fixed string: pgx's connect error names the DB
// login role, database, host and port, and this endpoint is reachable by
// anything on the network, so the detail goes to the server log only.
func readyzHandler(db dbPinger, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if db != nil {
			if err := db.Ping(r.Context()); err != nil {
				log.Warn("readiness check failed: database unreachable", "error", err.Error())
				http.Error(w, "database unreachable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready")) //nolint:errcheck // probe client went away
	}
}
