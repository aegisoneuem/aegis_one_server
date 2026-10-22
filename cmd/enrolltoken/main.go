// enrolltoken manages agent enrollment tokens (enrollment_tokens): the
// bootstrap credential an agent presents on its first Enroll call (agent config
// AEGIS_ENROLL_TOKEN). Needs AEGIS_DATABASE_URL.
//
//	go run ./cmd/enrolltoken mint   [-max-uses 1] [-days 7]
//	go run ./cmd/enrolltoken list
//	go run ./cmd/enrolltoken revoke -token-id <uuid>
//
// Defaults are the least-privilege choice (one device, one week); raise
// -max-uses for a fleet rollout. The raw token is printed once - only its
// SHA-256 is stored. Every successful enrollment uses one (re-enrolling a known
// device included). Mint and revoke go to audit_log as actor_type 'os_admin'.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"time"

	"aegis-one/internal/config"
	"aegis-one/internal/db"
	"aegis-one/internal/enroll"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: enrolltoken mint|list|revoke [flags]")
	}
	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		fatalf("AEGIS_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := db.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fatalf("database connection failed: %v", err)
	}
	defer pool.Close()

	switch os.Args[1] {
	case "mint":
		mint(ctx, pool, os.Args[2:])
	case "list":
		list(ctx, pool)
	case "revoke":
		revoke(ctx, pool, os.Args[2:])
	default:
		fatalf("unknown subcommand %q (want mint, list or revoke)", os.Args[1])
	}
}

func mint(ctx context.Context, pool *pgxpool.Pool, args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	maxUses := fs.Int("max-uses", 1, "how many enrollments this token allows")
	days := fs.Int("days", 7, "token lifetime in days (1-365)")
	fs.Parse(args)
	if *maxUses < 1 {
		fatalf("-max-uses must be at least 1")
	}
	if *days < 1 || *days > 365 {
		fatalf("-days must be between 1 and 365")
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fatalf("generate token: %v", err)
	}
	raw := "aet_" + base64.RawURLEncoding.EncodeToString(b)
	expires := time.Now().AddDate(0, 0, *days)

	tx, err := pool.Begin(ctx)
	if err != nil {
		fatalf("%v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO enrollment_tokens (token_hash, max_uses, expires_at)
		VALUES ($1, $2, $3) RETURNING id`, enroll.HashToken(raw), *maxUses, expires).Scan(&id); err != nil {
		fatalf("store token: %v", err)
	}
	details, _ := json.Marshal(map[string]any{"max_uses": *maxUses, "expires_at": expires.Format(time.RFC3339)})
	audit(ctx, tx, "enrollment_token.mint", id, string(details))
	if err := tx.Commit(ctx); err != nil {
		fatalf("commit: %v", err)
	}
	fmt.Printf("token_id:   %s\nmax_uses:   %d\nexpires_at: %s\n\n", id, *maxUses, expires.Format(time.RFC3339))
	fmt.Println("ENROLL TOKEN (shown once; give it to the agent as AEGIS_ENROLL_TOKEN):")
	fmt.Println(raw)
}

func list(ctx context.Context, pool *pgxpool.Pool) {
	rows, err := pool.Query(ctx, `
		SELECT id, use_count, max_uses, expires_at, revoked_at, created_at
		FROM enrollment_tokens ORDER BY created_at`)
	if err != nil {
		fatalf("%v", err)
	}
	defer rows.Close()
	fmt.Printf("%-36s  %-9s %-11s %s\n", "TOKEN_ID", "USES", "EXPIRES", "STATE")
	for rows.Next() {
		var id string
		var used, max int
		var expires, created time.Time
		var revoked *time.Time
		if err := rows.Scan(&id, &used, &max, &expires, &revoked, &created); err != nil {
			fatalf("%v", err)
		}
		state := "active"
		switch {
		case revoked != nil:
			state = "revoked"
		case time.Now().After(expires):
			state = "expired"
		case used >= max:
			state = "used up"
		}
		fmt.Printf("%-36s  %-9s %-11s %s\n", id, fmt.Sprintf("%d/%d", used, max), expires.Format("2006-01-02"), state)
	}
}

func revoke(ctx context.Context, pool *pgxpool.Pool, args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	tokenID := fs.String("token-id", "", "token id from 'enrolltoken list'")
	fs.Parse(args)
	if *tokenID == "" {
		fatalf("revoke needs -token-id")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		fatalf("%v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	tag, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at = now() WHERE id = $1::uuid AND revoked_at IS NULL`, *tokenID)
	if err != nil {
		fatalf("revoke: %v", err)
	}
	if tag.RowsAffected() == 0 {
		fatalf("no active token with id %s", *tokenID)
	}
	audit(ctx, tx, "enrollment_token.revoke", *tokenID, `{}`)
	if err := tx.Commit(ctx); err != nil {
		fatalf("commit: %v", err)
	}
	fmt.Println("revoked", *tokenID)
}

func audit(ctx context.Context, tx pgx.Tx, action, tokenID, details string) {
	label := "unknown"
	if u, err := user.Current(); err == nil {
		label = "os:" + u.Username
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (source, actor_type, actor_label, action, target_type, target_id, details)
		VALUES ('application', 'os_admin', $1, $2, 'enrollment_token', $3, $4::jsonb)`,
		label, action, tokenID, details); err != nil {
		fatalf("audit_log: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "enrolltoken: "+format+"\n", args...)
	os.Exit(1)
}
