package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

// A database failure must not echo pgx's connect error (DB user, database,
// host:port) to the unauthenticated probe.
func TestReadyzHidesDatabaseError(t *testing.T) {
	leaky := errors.New("failed to connect to `user=aegis_app database=aegis`: 10.0.0.5:5432 (db.internal): dial error: connection refused")
	var logged strings.Builder
	log := slog.New(slog.NewTextHandler(&logged, nil))

	rec := httptest.NewRecorder()
	readyzHandler(fakePinger{err: leaky}, log).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	for _, secret := range []string{"user=", "aegis_app", "10.0.0.5", "5432", "db.internal"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("body leaks %q: %s", secret, body)
		}
	}
	if !strings.Contains(string(body), "database unreachable") {
		t.Errorf("body = %q, want a generic message", body)
	}
	if !strings.Contains(logged.String(), "aegis_app") {
		t.Error("the real error should be in the server log")
	}
}

func TestReadyzOK(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, db := range []dbPinger{nil, fakePinger{}} {
		rec := httptest.NewRecorder()
		readyzHandler(db, log).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "ready" {
			t.Errorf("db=%v: %d %q", db, rec.Code, rec.Body.String())
		}
	}
}
