// Package vaultsdk provides a Go client SDK for the Vault Crypto Plugin.
//
// The SDK offers a type-safe interface for interacting with all plugin API
// endpoints, including key management, data signing, and EVM transaction
// building.
//
// # Quick Start
//
//	client, err := vaultsdk.NewClient("https://vault.example.com:8200", "s.my-token")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	key, err := client.CreateKey(ctx, &vaultsdk.CreateKeyRequest{
//	    Curve: "secp256k1",
//	    Name:  "my-eth-key",
//	})
//
// # TLS with Self-Signed Certificates
//
// Production Vault instances often use self-signed TLS certificates. The SDK
// provides several options for configuring TLS:
//
//	// Load CA cert from file (most common)
//	client, err := vaultsdk.NewClient(addr, token,
//	    vaultsdk.WithCACert("/etc/vault/ca.pem"),
//	)
//
//	// Load CA cert from PEM bytes (e.g., from Kubernetes Secrets)
//	client, err := vaultsdk.NewClient(addr, token,
//	    vaultsdk.WithCAPEM(caPEM),
//	)
//
//	// Provide a custom tls.Config (e.g., mutual TLS)
//	client, err := vaultsdk.NewClient(addr, token,
//	    vaultsdk.WithTLSConfig(tlsCfg),
//	)
package vaultsdk
