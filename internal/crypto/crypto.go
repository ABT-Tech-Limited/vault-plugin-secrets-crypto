// Package crypto provides cryptographic operations for the secrets engine.
package crypto

import (
	"fmt"

	"github.com/example/vault-plugin-secrets-crypto/internal/model"
)

// Signer defines the interface for cryptographic signing operations.
type Signer interface {
	// GenerateKey generates a new private key and returns its raw bytes.
	GenerateKey() ([]byte, error)

	// Sign signs the data and returns the signature.
	// If prehashed is true, the data is already hashed (32 bytes for ECDSA).
	// If prehashed is false, the signer will hash the data first.
	Sign(data []byte, prehashed bool) ([]byte, error)

	// PublicKey returns the public key bytes.
	// For secp256k1/secp256r1: uncompressed format (65 bytes: 0x04 || X || Y)
	// For ed25519: 32 bytes
	PublicKey() ([]byte, error)

	// Curve returns the curve type.
	Curve() model.CurveType
}

// NewSigner creates a new signer for the specified curve without a private key.
// Use GenerateKey() to generate a new key.
func NewSigner(curve model.CurveType) (Signer, error) {
	switch curve {
	case model.CurveSecp256k1:
		return NewSecp256k1Signer(nil)
	case model.CurveSecp256r1:
		return NewSecp256r1Signer(nil)
	case model.CurveEd25519:
		return NewEd25519Signer(nil)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// NewSignerWithKey creates a signer with an existing private key.
func NewSignerWithKey(curve model.CurveType, privateKey []byte) (Signer, error) {
	switch curve {
	case model.CurveSecp256k1:
		return NewSecp256k1Signer(privateKey)
	case model.CurveSecp256r1:
		return NewSecp256r1Signer(privateKey)
	case model.CurveEd25519:
		return NewEd25519Signer(privateKey)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}
