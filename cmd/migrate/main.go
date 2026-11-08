// migrate applies the database migrations embedded in this binary
// (db/migrations) and tracks them in schema_migrations. Run it on every
// deploy, before starting the server.
//
//	migrate status                  what is applied, what is pending
//	migrate up                      apply pending migrations (+ re-apply 0004 grants)
//	migrate baseline -through 0016  record 0001..0016 as applied WITHOUT running
//	                                them (a database migrated by hand earlier)
//
// Connects with AEGIS_MIGRATE_DATABASE_URL, which must be the schema owner
// (it runs DDL) - never the server's aegis_app login role. Keep that URL out
// of the server's own environment.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"aegis-one/db"
	"aegis-one/internal/dbmigrate"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	all, err := dbmigrate.Load(db.Migrations)
	if err != nil {
		fail("load migrations: %v", err)
	}

	url := strings.TrimSpace(os.Getenv("AEGIS_MIGRATE_DATABASE_URL"))
	if url == "" {
		fail("set AEGIS_MIGRATE_DATABASE_URL to the schema owner's connection URL (not the aegis_app login)")
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	pool, err := pgxpool.New(cctx, url)
	if err == nil {
		err = pool.Ping(cctx)
	}
	cancel()
	if err != nil {
		fail("connect: %v", err)
	}
	defer pool.Close()
	logf := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }

	switch os.Args[1] {
	case "status":
		status(ctx, pool, all)
	case "up":
		done, err := dbmigrate.Up(ctx, pool, all, logf)
		if err != nil {
			fail("migrate up: %v", err)
		}
		if len(done) == 0 {
			fmt.Println("database is up to date")
		} else {
			fmt.Printf("done: %d migration(s) applied\n", len(done))
		}
	case "baseline":
		fs := flag.NewFlagSet("baseline", flag.ExitOnError)
		through := fs.String("through", "", "last migration already applied by hand, e.g. 0016")
		_ = fs.Parse(os.Args[2:])
		if *through == "" {
			fail("baseline needs -through NNNN (the last migration this database already has)")
		}
		done, err := dbmigrate.Baseline(ctx, pool, all, *through, logf)
		if err != nil {
			fail("baseline: %v", err)
		}
		fmt.Printf("done: %d migration(s) recorded as applied; now run 'migrate up' for the rest\n", len(done))
	default:
		usage()
	}
}

func status(ctx context.Context, pool *pgxpool.Pool, all []dbmigrate.Migration) {
	applied, err := dbmigrate.ReadApplied(ctx, pool)
	if errors.Is(err, dbmigrate.ErrNoTable) {
		fmt.Println("no migration history (schema_migrations missing):")
		fmt.Println("  - empty database: run 'migrate up'")
		fmt.Println("  - migrated by hand: run 'migrate baseline -through NNNN' first")
		applied = map[string]dbmigrate.Applied{}
	} else if err != nil {
		fail("read schema_migrations: %v", err)
	}
	pendingCount := 0
	for _, m := range all {
		a, ok := applied[m.Version]
		switch {
		case !ok:
			pendingCount++
			fmt.Printf("  pending   %s\n", m.Name)
		case a.Checksum != m.Checksum:
			fmt.Printf("  CHANGED   %s  (file differs from what was applied - add a new migration instead)\n", m.Name)
		default:
			fmt.Printf("  %-9s %s  %s\n", a.Method, m.Name, a.AppliedAt.Format(time.RFC3339))
		}
	}
	fmt.Printf("%d pending\n", pendingCount)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: migrate status | up | baseline -through NNNN   (needs AEGIS_MIGRATE_DATABASE_URL)")
	os.Exit(2)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "migrate: "+format+"\n", args...)
	os.Exit(1)
}
