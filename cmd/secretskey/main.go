// Command secretskey creates the secrets master key file (internal/secretbox)
// that seals per-device agent unprotect passcodes in the database.
//
//	AEGIS_SECRETS_KEY_PASSPHRASE=<at least 16 chars> go run ./cmd/secretskey -out secrets/secrets.key.enc
//
// (or AEGIS_SECRETS_KEY_PASSPHRASE_FILE). It refuses to overwrite an existing
// file: losing the old key makes every stored passcode unreadable (the agents
// keep working; the server then rotates them, see docs/agent-operations-api.md).
// Back the file up together with the database, and keep the passphrase apart.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aegis-one/internal/config"
	"aegis-one/internal/secretbox"
)

func main() {
	out := flag.String("out", "secrets/secrets.key.enc", "where to write the sealed key file")
	flag.Parse()
	pass, err := config.SecretsKeyPassphrase()
	if err != nil {
		fail(err)
	}
	if pass == "" {
		fail(fmt.Errorf("set AEGIS_SECRETS_KEY_PASSPHRASE or AEGIS_SECRETS_KEY_PASSPHRASE_FILE"))
	}
	if _, err := os.Stat(*out); err == nil {
		fail(fmt.Errorf("%s already exists; refusing to overwrite (stored passcodes would become unreadable)", *out))
	}
	data, err := secretbox.NewKeyFile(pass)
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		fail(err)
	}
	// O_EXCL: never clobber a key file created in the meantime.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fail(err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		fail(err)
	}
	if err := f.Close(); err != nil {
		fail(err)
	}
	fmt.Println("wrote", *out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "secretskey:", err)
	os.Exit(1)
}
