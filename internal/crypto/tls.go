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

// HTTPServerTLSConfig loads the HTTPS API's certificate. Server-auth only (API
// callers authenticate with bearer tokens, not client certs). Minimum TLS 1.2,
// not the agent channel's 1.3: corporate proxies and scanners in front of the
// API/console still commonly speak only 1.2. Loaded at startup so a missing or
// bad cert fails fast instead of on the first request.
func HTTPServerTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load HTTP TLS cert/key: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
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
