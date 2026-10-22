// cagen creates the server's enrollment CA: a CA certificate, its private key
// ENCRYPTED with a passphrase (internal/ca format), and a server TLS certificate
// signed by that CA - agents verify the server against the same CA that issues
// their client certs at enrollment.
//
//	AEGIS_CA_KEY_PASSPHRASE=... go run ./cmd/cagen [-out certs] [-dns localhost,aegis-server] [-ip 127.0.0.1,::1]
//
// The passphrase can instead come from a file: AEGIS_CA_KEY_PASSPHRASE_FILE.
// Existing files are never overwritten. The server TLS key (server.key) is a
// plain 0600 file, as for any TLS server; only the CA key is passphrase-sealed.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aegis-one/internal/ca"
	"aegis-one/internal/config"
)

func main() {
	out := flag.String("out", "certs", "output directory")
	dns := flag.String("dns", "localhost,aegis-server", "server certificate DNS names (comma-separated)")
	ips := flag.String("ip", "127.0.0.1,::1", "server certificate IP addresses (comma-separated)")
	org := flag.String("org", "Aegis One", "organization name in the certificates")
	flag.Parse()

	passphrase, err := config.CAKeyPassphrase()
	if err != nil {
		fatalf("%v", err)
	}
	if len(passphrase) < ca.MinPassphraseLen {
		fatalf("set AEGIS_CA_KEY_PASSPHRASE (or _FILE) to at least %d characters", ca.MinPassphraseLen)
	}

	paths := map[string]string{
		"ca.crt": filepath.Join(*out, "ca.crt"), "ca.key.enc": filepath.Join(*out, "ca.key.enc"),
		"server.crt": filepath.Join(*out, "server.crt"), "server.key": filepath.Join(*out, "server.key"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			fatalf("%s already exists - refusing to overwrite an existing CA/PKI", p)
		}
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatalf("create %s: %v", *out, err)
	}

	now := time.Now()
	caKey := newKey()
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: *org + " Enrollment CA", Organization: []string{*org}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true, // signs leaf certs only, never another CA
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		fatalf("create CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	encKey, err := ca.EncryptKey(caKey, passphrase)
	if err != nil {
		fatalf("encrypt CA key: %v", err)
	}

	srvKey := newKey()
	srvTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "aegis-server", Organization: []string{*org}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     splitList(*dns),
	}
	for _, s := range splitList(*ips) {
		ip := net.ParseIP(s)
		if ip == nil {
			fatalf("invalid -ip value %q", s)
		}
		srvTmpl.IPAddresses = append(srvTmpl.IPAddresses, ip)
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		fatalf("create server cert: %v", err)
	}
	srvKeyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		fatalf("marshal server key: %v", err)
	}

	write(paths["ca.crt"], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)
	write(paths["ca.key.enc"], encKey, 0o600)
	write(paths["server.crt"], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}), 0o644)
	write(paths["server.key"], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER}), 0o600)

	fmt.Printf("wrote enrollment CA + server cert to %s\n", *out)
	fmt.Println("  ca.crt      -> give to agents (AEGIS_TLS_CA); the server uses it to verify client certs")
	fmt.Println("  ca.key.enc  -> CA private key, encrypted; server needs AEGIS_CA_KEY_PASSPHRASE to use it")
	fmt.Println("  server.crt/.key -> the server's TLS identity")
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func newKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatalf("generate key: %v", err)
	}
	return k
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fatalf("serial: %v", err)
	}
	return n
}

func write(path string, data []byte, mode os.FileMode) {
	if err := os.WriteFile(path, data, mode); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cagen: "+format+"\n", args...)
	os.Exit(1)
}
