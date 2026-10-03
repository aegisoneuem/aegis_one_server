// certgen generates a DEV mTLS trust set: a self-signed CA, a server cert, and a
// client cert (both signed by the CA). Development/testing only - in production
// certs come from the product's managed PKI or the customer's CA. Matches the
// same on-disk layout (PEM ca.crt / server.crt+key / client.crt+key) the agent's
// own cmd/certgen produces, so a cert pair generated here also works for testing
// the real agent binary against this server.
//
// Usage: go run ./cmd/certgen [out-dir]   (default ./certs)
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	outDir := "certs"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal("create out dir", err)
	}

	now := time.Now()

	caKey := newKey()
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Aegis One Dev CA", Organization: []string{"Aegis One"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		fatal("create CA", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	write(outDir, "ca", caDER, caKey)

	srvKey := newKey()
	srvTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "aegis-server", Organization: []string{"Aegis One"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "aegis-server"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		fatal("create server cert", err)
	}
	write(outDir, "server", srvDER, srvKey)

	cliKey := newKey()
	cliTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "aegis-agent", Organization: []string{"Aegis One"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		fatal("create client cert", err)
	}
	write(outDir, "client", cliDER, cliKey)

	fmt.Printf("wrote CA, server, client certs to %s\n", outDir)
	fmt.Println("  server uses: server.crt + server.key + ca.crt")
	fmt.Println("  agent  uses: client.crt + client.key + ca.crt")
}

func newKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("generate key", err)
	}
	return k
}

func serial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		fatal("serial", err)
	}
	return n
}

func write(dir, name string, certDER []byte, key *ecdsa.PrivateKey) {
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")

	certOut, err := os.Create(certPath)
	if err != nil {
		fatal("create "+certPath, err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		fatal("encode cert", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fatal("marshal key", err)
	}
	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fatal("create "+keyPath, err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		fatal("encode key", err)
	}
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "certgen: %s: %v\n", what, err)
	os.Exit(1)
}
