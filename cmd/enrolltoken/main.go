// enrolltoken manages agent enrollment tokens (enrollment_tokens): the
// bootstrap credential an agent presents on its first Enroll call (agent config
// AEGIS_ENROLL_TOKEN). Needs AEGIS_DATABASE_URL.
//
//	go run ./cmd/enrolltoken mint   [-max-uses 1] [-days 7]
//	go run ./cmd/enrolltoken mint   -reenroll <device_id> [-days 1]
//	go run ./cmd/enrolltoken list
//	go run ./cmd/enrolltoken revoke -token-id <uuid>
//
// Defaults are the least-privilege choice (one device, one week); raise
// -max-uses for a fleet rollout. A plain token only enrolls NEW devices and
// brings back RETIRED ones (or ones whose certificates have expired); it can
// not take over a device that still holds a valid certificate. To reinstall
// the agent on such a device without retiring it first, mint a token bound to
// it with -reenroll: single use, short-lived, and good for nothing else. The
// raw token is printed once - only its SHA-256 is stored. Every successful
// enrollment uses one. Mint and revoke go to audit_log as actor_type 'os_admin'.
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
	"regexp"
	"strings"
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
	days := fs.Int("days", 0, "token lifetime in days (1-365; default 7, or 1 with -reenroll)")
	reenroll := fs.String("reenroll", "", "bind the token to this device_id: it may only re-enroll that device (single use)")
	fs.Parse(args)
	*reenroll = strings.ToLower(strings.TrimSpace(*reenroll))
	if *days == 0 {
		*days = 7
		if *reenroll != "" {
			*days = 1
		}
	}
	if *maxUses < 1 {
		fatalf("-max-uses must be at least 1")
	}
	if *days < 1 || *days > 365 {
		fatalf("-days must be between 1 and 365")
	}
	scope := "{}"
	if *reenroll != "" {
		if !uuidRe.MatchString(*reenroll) {
			fatalf("-reenroll must be the device's device_id (a UUID, as shown by /internal/devices)")
		}
		if *maxUses != 1 {
			fatalf("a -reenroll token is single use (-max-uses 1)")
		}
		if *days > 7 {
			fatalf("a -reenroll token lives at most 7 days")
		}
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE agent_reported_id = $1 AND merged_into_device_id IS NULL)`,
			*reenroll).Scan(&exists); err != nil {
			fatalf("look up device: %v", err)
		}
		if !exists {
			fatalf("no device with device_id %s", *reenroll)
		}
		b, _ := json.Marshal(map[string]string{"reenroll_device_id": *reenroll})
		scope = string(b)
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
		INSERT INTO enrollment_tokens (token_hash, max_uses, expires_at, scope)
		VALUES ($1, $2, $3, $4::jsonb) RETURNING id`, enroll.HashToken(raw), *maxUses, expires, scope).Scan(&id); err != nil {
		fatalf("store token: %v", err)
	}
	details, _ := json.Marshal(map[string]any{"max_uses": *maxUses, "expires_at": expires.Format(time.RFC3339), "reenroll_device_id": *reenroll})
	audit(ctx, tx, "enrollment_token.mint", id, string(details))
	if err := tx.Commit(ctx); err != nil {
		fatalf("commit: %v", err)
	}
	fmt.Printf("token_id:   %s\nmax_uses:   %d\nexpires_at: %s\n", id, *maxUses, expires.Format(time.RFC3339))
	if *reenroll != "" {
		fmt.Printf("bound to:   device %s (re-enroll only)\n", *reenroll)
	}
	fmt.Println("\nENROLL TOKEN (shown once; give it to the agent as AEGIS_ENROLL_TOKEN):")
	fmt.Println(raw)
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func list(ctx context.Context, pool *pgxpool.Pool) {
	rows, err := pool.Query(ctx, `
		SELECT id, use_count, max_uses, expires_at, revoked_at, created_at, coalesce(scope->>'reenroll_device_id', '')
		FROM enrollment_tokens ORDER BY created_at`)
	if err != nil {
		fatalf("%v", err)
	}
	defer rows.Close()
	fmt.Printf("%-36s  %-9s %-11s %-8s %s\n", "TOKEN_ID", "USES", "EXPIRES", "STATE", "BOUND_TO")
	for rows.Next() {
		var id, bound string
		var used, max int
		var expires, created time.Time
		var revoked *time.Time
		if err := rows.Scan(&id, &used, &max, &expires, &revoked, &created, &bound); err != nil {
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
		fmt.Printf("%-36s  %-9s %-11s %-8s %s\n", id, fmt.Sprintf("%d/%d", used, max), expires.Format("2006-01-02"), state, bound)
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
