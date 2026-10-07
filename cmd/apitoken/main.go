// apitoken manages platform API tokens for the /internal/* endpoints - the
// bootstrap path until an admin console exists. Needs AEGIS_DATABASE_URL.
//
//	go run ./cmd/apitoken mint   -client ops-team -role operator -scopes patch.deploy,reports.view [-days 90]
//	go run ./cmd/apitoken list
//	go run ./cmd/apitoken revoke -token-id <uuid>
//
// mint creates the client if it doesn't exist (then -role is required) and
// prints the raw token ONCE - only its hash is stored. Scopes use role
// permission names (patch.deploy, reports.view, agent.command, ...) or "*".
// Mint and revoke are written to audit_log as actor_type 'os_admin'.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"aegis-one/internal/apiauth"
	"aegis-one/internal/config"
	"aegis-one/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: apitoken mint|list|revoke [flags]")
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
	client := fs.String("client", "", "api client name (created if missing)")
	role := fs.String("role", "", "role for a NEW client: admin, operator, auditor, read_only, ...")
	scopes := fs.String("scopes", "", "comma-separated permissions this token may use, or *")
	days := fs.Int("days", 90, "token lifetime in days (1-365)")
	fs.Parse(args)

	if *client == "" || *scopes == "" {
		fatalf("mint needs -client and -scopes")
	}
	if *days < 1 || *days > 365 {
		fatalf("-days must be between 1 and 365")
	}
	var scopeList []string
	for _, s := range strings.Split(*scopes, ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopeList = append(scopeList, s)
		}
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		fatalf("%v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	var clientID, clientRole string
	err = tx.QueryRow(ctx, `
		SELECT c.id, r.name FROM api_clients c JOIN roles r ON r.id = c.role_id
		WHERE c.name = $1 AND c.disabled_at IS NULL`, *client).Scan(&clientID, &clientRole)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if *role == "" {
			fatalf("client %q does not exist - pass -role to create it", *client)
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO api_clients (name, role_id)
			SELECT $1, id FROM roles WHERE name = $2
			RETURNING id`, *client, *role).Scan(&clientID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				fatalf("unknown role %q", *role)
			}
			fatalf("create client: %v", err)
		}
		clientRole = *role
		fmt.Printf("created api client %q with role %q\n", *client, *role)
	case err != nil:
		fatalf("look up client: %v", err)
	case *role != "" && *role != clientRole:
		fatalf("client %q already has role %q; refusing to change it to %q here", *client, clientRole, *role)
	}

	raw, hash, err := apiauth.NewToken()
	if err != nil {
		fatalf("generate token: %v", err)
	}
	expires := time.Now().AddDate(0, 0, *days)
	var tokenID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO api_tokens (api_client_id, token_hash, scopes, expires_at)
		VALUES ($1, $2, $3, $4) RETURNING id`, clientID, hash, scopeList, expires).Scan(&tokenID); err != nil {
		fatalf("store token: %v", err)
	}
	details, _ := json.Marshal(map[string]any{"client": *client, "scopes": scopeList, "expires_at": expires.Format(time.RFC3339)})
	audit(ctx, tx, "api_token.mint", tokenID, string(details))
	if err := tx.Commit(ctx); err != nil {
		fatalf("commit: %v", err)
	}

	fmt.Printf("token_id:   %s\nclient:     %s (role %s)\nscopes:     %s\nexpires_at: %s\n\n",
		tokenID, *client, clientRole, strings.Join(scopeList, ","), expires.Format(time.RFC3339))
	fmt.Println("TOKEN (shown once, store it securely - only its hash is kept):")
	fmt.Println(raw)
}

func list(ctx context.Context, pool *pgxpool.Pool) {
	rows, err := pool.Query(ctx, `
		SELECT t.id, c.name, r.name, array_to_string(t.scopes, ','), t.expires_at, t.revoked_at, t.last_used_at
		FROM api_tokens t JOIN api_clients c ON c.id = t.api_client_id JOIN roles r ON r.id = c.role_id
		ORDER BY t.created_at`)
	if err != nil {
		fatalf("%v", err)
	}
	defer rows.Close()
	fmt.Printf("%-36s  %-16s %-10s %-28s %-10s %s\n", "TOKEN_ID", "CLIENT", "ROLE", "SCOPES", "EXPIRES", "STATE")
	for rows.Next() {
		var id, client, role, scopes string
		var expires time.Time
		var revoked, lastUsed *time.Time
		if err := rows.Scan(&id, &client, &role, &scopes, &expires, &revoked, &lastUsed); err != nil {
			fatalf("%v", err)
		}
		state := "active"
		switch {
		case revoked != nil:
			state = "revoked"
		case time.Now().After(expires):
			state = "expired"
		}
		if lastUsed != nil {
			state += ", last used " + lastUsed.Format("2006-01-02 15:04")
		}
		fmt.Printf("%-36s  %-16s %-10s %-28s %-10s %s\n", id, client, role, scopes, expires.Format("2006-01-02"), state)
	}
}

func revoke(ctx context.Context, pool *pgxpool.Pool, args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	tokenID := fs.String("token-id", "", "token id from 'apitoken list'")
	fs.Parse(args)
	if *tokenID == "" {
		fatalf("revoke needs -token-id")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		fatalf("%v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	tag, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE id = $1::uuid AND revoked_at IS NULL`, *tokenID)
	if err != nil {
		fatalf("revoke: %v", err)
	}
	if tag.RowsAffected() == 0 {
		fatalf("no active token with id %s", *tokenID)
	}
	audit(ctx, tx, "api_token.revoke", *tokenID, `{}`)
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
		VALUES ('application', 'os_admin', $1, $2, 'api_token', $3, $4::jsonb)`,
		label, action, tokenID, details); err != nil {
		fatalf("audit_log: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "apitoken: "+format+"\n", args...)
	os.Exit(1)
}
