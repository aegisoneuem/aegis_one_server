// keygen generates the Ed25519 command-signing keypair. The private key is
// written to a local gitignored file for the server to sign with (internal/signing);
// the public key must be handed to whoever builds the agent, since this contract
// (proto/agentcontrol/v1) verifies commands against a single hardcoded public key
// baked into the agent binary - there is no key rotation or wire delivery here.
//
// Usage: go run ./cmd/keygen [out-file]   (default ./secrets/command_signing.key)
//
// With AEGIS_DATABASE_URL set, it also records the public key in signing_keys
// with status='pending' (never 'active' - promoting a key is a deliberate,
// separate decision once the agent has actually been rebuilt to trust it).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"aegis-one/internal/config"
	"aegis-one/internal/db"
)

func main() {
	outPath := "secrets/command_signing.key"
	if len(os.Args) > 1 {
		outPath = os.Args[1]
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("generate key: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fatalf("create secrets dir: %v", err)
	}
	privB64 := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(outPath, []byte(privB64+"\n"), 0o600); err != nil {
		fatalf("write private key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	fmt.Printf("wrote private key to %s (gitignored, mode 0600)\n", outPath)
	fmt.Printf("PUBLIC_KEY=%s\n", pubB64)
	fmt.Println("Give PUBLIC_KEY to whoever builds the agent - it must replace the")
	fmt.Println("hardcoded publicKeyB64 in cmd/agent/main.go, then the agent needs rebuilding.")

	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		fmt.Println("AEGIS_DATABASE_URL not set - public key NOT recorded in signing_keys.")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := db.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fatalf("database connection failed: %v", err)
	}
	defer pool.Close()

	var id string
	err = pool.QueryRow(ctx, `
		INSERT INTO signing_keys (key_purpose, public_key, vault_key_ref, status)
		VALUES ('command_signing', $1, $2, 'pending')
		RETURNING id`,
		pubB64, "local-file:"+outPath).Scan(&id)
	if err != nil {
		fatalf("insert into signing_keys: %v", err)
	}
	fmt.Printf("recorded in signing_keys as %s, status='pending'\n", id)
	fmt.Println("Promote it to 'active' only after the agent has been rebuilt to trust this key.")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "keygen: "+format+"\n", args...)
	os.Exit(1)
}
