// Package backend implements the Vault secrets engine backend.
package backend

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// Version is the semantic version of the plugin.
	Version = "v0.1.0"

	// PluginDescription provides a brief description of the plugin.
	PluginDescription = "Cryptographic key management for blockchain applications"
)

// CryptoBackend is the main backend for the crypto secrets engine.
type CryptoBackend struct {
	*framework.Backend
	lock sync.RWMutex
}

// Factory creates a new CryptoBackend instance.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() *CryptoBackend {
	b := &CryptoBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"keys/*", // Enable SealWrap for all key storage
			},
		},
		Paths: framework.PathAppend(
			pathKeys(b),
			pathKeysSign(b),
		),
		BackendType:    logical.TypeLogical,
		Invalidate:     b.invalidate,
		RunningVersion: Version,
	}

	return b
}

func (b *CryptoBackend) invalidate(ctx context.Context, key string) {
	// Called when storage is invalidated
	// Currently no caching to invalidate
}

const backendHelp = `
The crypto secrets engine manages cryptographic keys for blockchain applications.

Supported curves:
- secp256k1: For EVM-compatible chains (Ethereum, BSC, Polygon, etc.) and Bitcoin
- secp256r1: For general ECDSA (P-256/prime256v1)
- ed25519: For Solana and other Ed25519-based systems

Features:
- Secure key generation and storage
- Private keys never leave Vault
- Signing operations with various output formats
- Unique key identification via internal_id, name, or external_id

Endpoints:
- POST   /keys              - Create a new key
- GET    /keys              - List all keys
- GET    /keys/:internal_id - Read key info (no private key)
- POST   /keys/:internal_id/sign - Sign data

Security:
- Private keys are encrypted at rest using Vault's storage encryption
- SealWrap provides additional encryption layer for key material
- Private keys are never returned in any API response
- Keys cannot be deleted for security and audit compliance
`
