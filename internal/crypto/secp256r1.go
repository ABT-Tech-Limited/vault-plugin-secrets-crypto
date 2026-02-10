package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/model"
)

// Secp256r1Signer implements the Signer interface for P-256 (secp256r1) curve.
type Secp256r1Signer struct {
	privateKey *ecdsa.PrivateKey
}

// NewSecp256r1Signer creates a new secp256r1 (P-256) signer.
// If privateKeyBytes is nil, call GenerateKey() to create a new key.
func NewSecp256r1Signer(privateKeyBytes []byte) (*Secp256r1Signer, error) {
	signer := &Secp256r1Signer{}

	if privateKeyBytes != nil {
		if len(privateKeyBytes) != 32 {
			return nil, fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privateKeyBytes))
		}

		// Reconstruct private key from bytes
		curve := elliptic.P256()
		d := new(big.Int).SetBytes(privateKeyBytes)

		// Compute public key
		x, y := curve.ScalarBaseMult(privateKeyBytes)

		signer.privateKey = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			D: d,
		}
	}

	return signer, nil
}

// GenerateKey generates a new P-256 private key.
// Returns the private key D value as 32 bytes.
func (s *Secp256r1Signer) GenerateKey() ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	s.privateKey = privateKey

	// Convert D to 32 bytes (left-pad with zeros if necessary)
	dBytes := privateKey.D.Bytes()
	result := make([]byte, 32)
	copy(result[32-len(dBytes):], dBytes)

	return result, nil
}

// Sign signs the data using P-256.
// Returns signature in format: R (32 bytes) || S (32 bytes)
// Total 64 bytes.
func (s *Secp256r1Signer) Sign(data []byte, prehashed bool) ([]byte, error) {
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

	// Sign the hash
	r, sVal, err := ecdsa.Sign(rand.Reader, s.privateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Convert R and S to fixed 32 bytes each
	signature := make([]byte, 64)

	rBytes := r.Bytes()
	sBytes := sVal.Bytes()

	copy(signature[32-len(rBytes):32], rBytes) // R (left-pad with zeros)
	copy(signature[64-len(sBytes):64], sBytes) // S (left-pad with zeros)

	return signature, nil
}

// Curve returns the curve type.
func (s *Secp256r1Signer) Curve() model.CurveType {
	return model.CurveSecp256r1
}

// PublicKey returns the uncompressed public key (65 bytes: 0x04 || X || Y).
func (s *Secp256r1Signer) PublicKey() ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}
	return elliptic.Marshal(s.privateKey.Curve, s.privateKey.X, s.privateKey.Y), nil
}
