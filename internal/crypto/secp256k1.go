package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/model"
)

// Secp256k1Signer implements the Signer interface for secp256k1 curve.
// This is compatible with Ethereum and Bitcoin.
type Secp256k1Signer struct {
	privateKey *secp256k1.PrivateKey
}

// NewSecp256k1Signer creates a new secp256k1 signer.
// If privateKeyBytes is nil, call GenerateKey() to create a new key.
func NewSecp256k1Signer(privateKeyBytes []byte) (*Secp256k1Signer, error) {
	signer := &Secp256k1Signer{}

	if privateKeyBytes != nil {
		if len(privateKeyBytes) != 32 {
			return nil, fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privateKeyBytes))
		}
		signer.privateKey = secp256k1.PrivKeyFromBytes(privateKeyBytes)
	}

	return signer, nil
}

// GenerateKey generates a new secp256k1 private key.
// Returns the private key as 32 bytes.
func (s *Secp256k1Signer) GenerateKey() ([]byte, error) {
	// Generate 32 random bytes
	privateKeyBytes := make([]byte, 32)
	if _, err := rand.Read(privateKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create private key from bytes (validates the key is in valid range)
	s.privateKey = secp256k1.PrivKeyFromBytes(privateKeyBytes)

	// Return serialized key
	result := make([]byte, 32)
	copy(result, s.privateKey.Serialize())

	// Zero the temporary buffer
	ZeroBytes(privateKeyBytes)

	return result, nil
}

// Sign signs the data using secp256k1.
// Returns signature in format: R (32 bytes) || S (32 bytes) || V (1 byte)
// Total 65 bytes, compatible with Ethereum signature format.
// V is the recovery id (0 or 1).
func (s *Secp256k1Signer) Sign(data []byte, prehashed bool) ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}

	var hash []byte
	if prehashed {
		if len(data) != 32 {
			return nil, fmt.Errorf("prehashed data must be 32 bytes, got %d", len(data))
		}
		hash = data
	} else {
		// Hash the data with SHA-256
		h := sha256.Sum256(data)
		hash = h[:]
	}

	// Sign using compact recoverable signature
	// Format: [recovery_id + 27] || R (32 bytes) || S (32 bytes)
	compactSig := ecdsa.SignCompact(s.privateKey, hash, false)

	// Convert to Ethereum format: R || S || V
	// compactSig[0] is recovery_id + 27
	// compactSig[1:33] is R
	// compactSig[33:65] is S
	signature := make([]byte, 65)
	copy(signature[0:32], compactSig[1:33])  // R
	copy(signature[32:64], compactSig[33:65]) // S
	signature[64] = compactSig[0] - 27        // V (0 or 1)

	return signature, nil
}

// Curve returns the curve type.
func (s *Secp256k1Signer) Curve() model.CurveType {
	return model.CurveSecp256k1
}

// PublicKey returns the uncompressed public key (65 bytes: 0x04 || X || Y).
func (s *Secp256k1Signer) PublicKey() ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}
	pubKey := s.privateKey.PubKey()
	return pubKey.SerializeUncompressed(), nil
}
