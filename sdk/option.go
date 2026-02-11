package vaultsdk

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Option configures the client.
type Option func(*options) error

type options struct {
	mountPath  string
	timeout    time.Duration
	tlsConfig  *tls.Config
	httpClient *http.Client
}

// WithMountPath sets a custom mount path for the crypto secrets engine.
// Default: "crypto".
func WithMountPath(path string) Option {
	return func(o *options) error {
		o.mountPath = path
		return nil
	}
}

// WithTimeout sets the HTTP client timeout. Default: 30s.
func WithTimeout(d time.Duration) Option {
	return func(o *options) error {
		o.timeout = d
		return nil
	}
}

// WithTLSConfig provides a custom TLS configuration.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(o *options) error {
		o.tlsConfig = cfg
		return nil
	}
}

// WithCACert loads a PEM-encoded CA certificate from a file path
// and adds it to the TLS root CA pool. This is the most common way
// to configure TLS for Vault instances using self-signed certificates.
func WithCACert(path string) Option {
	return func(o *options) error {
		pem, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read CA cert file: %w", err)
		}
		return withCAPEM(pem)(o)
	}
}

// WithCAPEM adds a PEM-encoded CA certificate to the TLS root CA pool
// from raw bytes. Useful when the CA cert is loaded from environment
// variables or secret managers (e.g., Kubernetes Secrets).
func WithCAPEM(pem []byte) Option {
	return withCAPEM(pem)
}

func withCAPEM(pem []byte) Option {
	return func(o *options) error {
		if o.tlsConfig == nil {
			o.tlsConfig = &tls.Config{}
		}
		if o.tlsConfig.RootCAs == nil {
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			o.tlsConfig.RootCAs = pool
		}
		if !o.tlsConfig.RootCAs.AppendCertsFromPEM(pem) {
			return fmt.Errorf("failed to parse CA certificate PEM")
		}
		return nil
	}
}

// WithHTTPClient provides a fully custom *http.Client.
// When set, TLS options (WithTLSConfig, WithCACert, WithCAPEM)
// and WithTimeout are ignored.
func WithHTTPClient(client *http.Client) Option {
	return func(o *options) error {
		o.httpClient = client
		return nil
	}
}
