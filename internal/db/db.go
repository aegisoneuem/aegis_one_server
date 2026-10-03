// Package db holds the Postgres connection pool. The server connects as the
// least-privilege aegis_app role (see db/migrations/0004_db_roles.sql) - never
// as postgres/owner.
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// New opens a pgx connection pool against databaseURL. Callers should Ping (or
// rely on Pool.Ping via /readyz) before treating the server as ready.
func New(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}
