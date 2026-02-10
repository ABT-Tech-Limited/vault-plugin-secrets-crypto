package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/model"
)

// Ed25519Signer implements the Signer interface for Ed25519 curve.
// This is compatible with Solana and other Ed25519-based systems.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
}

// NewEd25519Signer creates a new Ed25519 signer.
// If privateKeyBytes is nil, call GenerateKey() to create a new key.
// privateKeyBytes can be either 32 bytes (seed) or 64 bytes (full private key).
func NewEd25519Signer(privateKeyBytes []byte) (*Ed25519Signer, error) {
	signer := &Ed25519Signer{}

	if privateKeyBytes != nil {
		switch len(privateKeyBytes) {
		case 32:
			// 32-byte seed, generate full private key
			signer.privateKey = ed25519.NewKeyFromSeed(privateKeyBytes)
		case 64:
			// Full 64-byte private key
			signer.privateKey = ed25519.PrivateKey(privateKeyBytes)
		default:
			return nil, fmt.Errorf("invalid private key length: expected 32 or 64 bytes, got %d", len(privateKeyBytes))
		}
	}

	return signer, nil
}

// GenerateKey generates a new Ed25519 private key.
// Returns the 32-byte seed (for compact storage).
func (s *Ed25519Signer) GenerateKey() ([]byte, error) {
	// Generate 32-byte seed
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create private key from seed
	s.privateKey = ed25519.NewKeyFromSeed(seed)

	// Return a copy of the seed
	result := make([]byte, 32)
	copy(result, seed)

	// Zero the temporary buffer
	ZeroBytes(seed)

	return result, nil
}

// Sign signs the data using Ed25519.
// Returns 64-byte signature.
// Note: Ed25519 internally hashes the message, so prehashed is typically false.
// If prehashed is true, the data is treated as already processed (Ed25519ph mode).
func (s *Ed25519Signer) Sign(data []byte, prehashed bool) ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}

	// Standard Ed25519 signing (internal SHA-512 hashing)
	// Note: For Ed25519ph (prehashed mode), you would use ed25519.SignWithOptions
	// with crypto.Hash set to crypto.SHA512. However, standard Solana uses
	// regular Ed25519, so we use the standard Sign function.
	signature := ed25519.Sign(s.privateKey, data)

	return signature, nil
}

// Curve returns the curve type.
func (s *Ed25519Signer) Curve() model.CurveType {
	return model.CurveEd25519
}

// PublicKey returns the 32-byte public key.
func (s *Ed25519Signer) PublicKey() ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}
	pubKey := s.privateKey.Public().(ed25519.PublicKey)
	return []byte(pubKey), nil
}
