// Package crypto builds the server's mTLS transport credentials. Mirrors the
// agent's internal/secure/tls.go (ServerCredentials side): the server presents
// its own cert/key and REQUIRES + verifies a client certificate against the CA.
// Security is mandatory, not toggleable - there is no insecure fallback.
package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

const minTLS = tls.VersionTLS13

func loadCAPool(caPath string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA %q: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in CA file %q", caPath)
	}
	return pool, nil
}

// ServerCredentials loads the server's mTLS transport credentials: it presents
// certPath/keyPath and requires + verifies a client cert against caPath.
func ServerCredentials(caPath, certPath, keyPath string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}
	pool, err := loadCAPool(caPath)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion:   minTLS,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}), nil
}
