// Package dbmigrate applies the embedded SQL migrations (db/migrations) and
// records them in schema_migrations, so each runs exactly once per database.
//
//   - Up applies every pending migration in file-name order, each in its own
//     transaction together with its schema_migrations row: a failed migration
//     leaves nothing behind and stops the run.
//   - After any run, 0004_db_roles.sql is applied again (it is re-runnable) so
//     the least-privilege grants cover tables added since.
//   - An applied migration whose file changed is refused: never edit an
//     applied migration, add a new numbered file.
//   - Baseline records migrations as applied without running them, for a
//     database that was migrated by hand before this tool existed.
//
// It must connect as the schema owner (DDL), never as the application's
// login role; the server only reads schema_migrations to refuse starting
// against a database that is behind its code (Pending).
package dbmigrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rolesFile is re-applied after every run so new tables get their grants.
const rolesFile = "0004_db_roles.sql"

// lockKey serializes migration runs (two deploys at once).
const lockKey = 0x41454749534d4947 // "AEGISMIG"

var nameRe = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

// Migration is one embedded SQL file.
type Migration struct {
	Version  string // "0017"
	Name     string // "0017_agent_inventory_audit.sql"
	SQL      string
	Checksum string // sha256 of the file with CRLF normalized to LF
}

// Load reads the migrations from fsys (the "migrations" directory inside it),
// sorted by version. Versions must be unique.
func Load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, err
	}
	var out []Migration
	seen := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := nameRe.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration file %q does not match NNNN_name.sql", e.Name())
		}
		if other, dup := seen[m[1]]; dup {
			return nil, fmt.Errorf("migration version %s used twice: %s and %s", m[1], other, e.Name())
		}
		seen[m[1]] = e.Name()
		b, err := fs.ReadFile(fsys, path.Join("migrations", e.Name()))
		if err != nil {
			return nil, err
		}
		sql := strings.ReplaceAll(string(b), "\r\n", "\n") // git autocrlf on Windows checkouts
		sum := sha256.Sum256([]byte(sql))
		out = append(out, Migration{Version: m[1], Name: e.Name(), SQL: sql, Checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Applied is one schema_migrations row.
type Applied struct {
	Version   string
	Name      string
	Checksum  string
	AppliedAt time.Time
	Method    string // applied | baseline
}

const createTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    checksum    TEXT NOT NULL,
    method      TEXT NOT NULL CHECK (method IN ('applied', 'baseline')),
    applied_by  TEXT NOT NULL DEFAULT current_user,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// ErrNoTable means schema_migrations doesn't exist: a new database (run Up)
// or one migrated by hand (run Baseline first).
var ErrNoTable = errors.New("schema_migrations does not exist")

// ReadApplied returns the recorded migrations by version.
func ReadApplied(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (map[string]Applied, error) {
	rows, err := q.Query(ctx, `SELECT version, name, checksum, applied_at, method FROM schema_migrations`)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" { // undefined_table
			return nil, ErrNoTable
		}
		return nil, err
	}
	defer rows.Close()
	out := map[string]Applied{}
	for rows.Next() {
		var a Applied
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt, &a.Method); err != nil {
			return nil, err
		}
		out[a.Version] = a
	}
	return out, rows.Err()
}

// Pending returns the migrations not yet recorded, and an error if a recorded
// one no longer matches its file.
func Pending(all []Migration, applied map[string]Applied) ([]Migration, error) {
	var pending []Migration
	for _, m := range all {
		a, ok := applied[m.Version]
		if !ok {
			pending = append(pending, m)
			continue
		}
		if a.Checksum != m.Checksum {
			return nil, fmt.Errorf("%s was changed after it was applied (recorded checksum %.12s, file %.12s); "+
				"never edit an applied migration - add a new numbered file", m.Name, a.Checksum, m.Checksum)
		}
	}
	return pending, nil
}

// Logf receives progress lines.
type Logf func(format string, args ...any)

// Up applies every pending migration, then re-applies the roles file.
// Returns the names applied.
func Up(ctx context.Context, pool *pgxpool.Pool, all []Migration, logf Logf) ([]string, error) {
	conn, err := lock(ctx, pool)
	if err != nil {
		return nil, err
	}
	defer unlock(conn)
	if _, err := conn.Exec(ctx, createTable); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := ReadApplied(ctx, conn)
	if err != nil {
		return nil, err
	}
	if len(applied) == 0 {
		var tables int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name IN ('devices', 'agents', 'audit_log')`).Scan(&tables); err != nil {
			return nil, err
		}
		if tables > 0 {
			return nil, errors.New("this database already has Aegis One tables but no migration history: " +
				"it was migrated by hand. Record what it has with 'migrate baseline -through NNNN' first")
		}
	}
	pending, err := Pending(all, applied)
	if err != nil {
		return nil, err
	}
	var done []string
	for _, m := range pending {
		start := time.Now()
		if err := apply(ctx, conn, m, "applied", true); err != nil {
			return done, fmt.Errorf("%s: %w", m.Name, err)
		}
		logf("applied %s (%s)", m.Name, time.Since(start).Round(time.Millisecond))
		done = append(done, m.Name)
	}
	if err := reapplyRoles(ctx, conn, all); err != nil {
		return done, err
	}
	logf("re-applied %s (grants for current tables)", rolesFile)
	return done, nil
}

// Baseline records every migration up to and including through as applied
// without running it, for a database migrated by hand. Already-recorded
// versions are left alone.
func Baseline(ctx context.Context, pool *pgxpool.Pool, all []Migration, through string, logf Logf) ([]string, error) {
	if !regexp.MustCompile(`^\d{4}$`).MatchString(through) {
		return nil, fmt.Errorf("-through must be a 4-digit version like 0016, got %q", through)
	}
	found := false
	for _, m := range all {
		if m.Version == through {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("no migration with version %s", through)
	}
	conn, err := lock(ctx, pool)
	if err != nil {
		return nil, err
	}
	defer unlock(conn)
	if _, err := conn.Exec(ctx, createTable); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := ReadApplied(ctx, conn)
	if err != nil {
		return nil, err
	}
	var done []string
	for _, m := range all {
		if m.Version > through {
			break
		}
		if _, ok := applied[m.Version]; ok {
			continue
		}
		if err := apply(ctx, conn, m, "baseline", false); err != nil {
			return done, fmt.Errorf("%s: %w", m.Name, err)
		}
		logf("recorded %s as already applied (baseline)", m.Name)
		done = append(done, m.Name)
	}
	return done, nil
}

// apply runs m (unless run is false) and records it, in one transaction.
func apply(ctx context.Context, conn *pgxpool.Conn, m Migration, method string, run bool) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if run {
		// No arguments: pgx uses the simple protocol, which runs a file of
		// several statements as written.
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name, checksum, method) VALUES ($1, $2, $3, $4)`,
		m.Version, m.Name, m.Checksum, method); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	return tx.Commit(ctx)
}

// reapplyRoles runs the roles file again and keeps the application role from
// rewriting the migration history (its blanket grant would otherwise cover it).
func reapplyRoles(ctx context.Context, conn *pgxpool.Conn, all []Migration) error {
	var roles *Migration
	for i := range all {
		if all[i].Name == rolesFile {
			roles = &all[i]
		}
	}
	if roles == nil {
		return fmt.Errorf("%s not found among the migrations", rolesFile)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, roles.SQL); err != nil {
		return fmt.Errorf("re-apply %s: %w", rolesFile, err)
	}
	if _, err := tx.Exec(ctx, `REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON schema_migrations FROM aegis_app`); err != nil {
		return fmt.Errorf("restrict schema_migrations: %w", err)
	}
	return tx.Commit(ctx)
}

func lock(ctx context.Context, pool *pgxpool.Pool) (*pgxpool.Conn, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, int64(lockKey)).Scan(&got); err != nil {
		conn.Release()
		return nil, err
	}
	if !got {
		conn.Release()
		return nil, errors.New("another migration run holds the lock; wait for it to finish")
	}
	return conn, nil
}

func unlock(conn *pgxpool.Conn) {
	_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, int64(lockKey))
	conn.Release()
}

// CheckCurrent is the server's startup check: the database must have every
// migration this build ships with, unchanged. It needs only SELECT on
// schema_migrations, so the application role can run it.
func CheckCurrent(ctx context.Context, pool *pgxpool.Pool, all []Migration) error {
	applied, err := ReadApplied(ctx, pool)
	if errors.Is(err, ErrNoTable) {
		return errors.New("the database has no migration history: run 'migrate up' (new database) or " +
			"'migrate baseline -through NNNN' then 'migrate up' (database migrated by hand)")
	}
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	pending, err := Pending(all, applied)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		names := make([]string, 0, len(pending))
		for _, m := range pending {
			names = append(names, m.Name)
		}
		return fmt.Errorf("%d migration(s) not applied yet (%s): run 'migrate up' before starting this version",
			len(pending), strings.Join(names, ", "))
	}
	return nil
}
