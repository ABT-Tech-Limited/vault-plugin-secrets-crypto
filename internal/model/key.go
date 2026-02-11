// Package model defines the data structures used in the crypto secrets engine.
package model

import (
	"time"
)

// CurveType defines the supported elliptic curve types.
type CurveType string

const (
	// CurveSecp256k1 is the secp256k1 curve used by EVM chains and Bitcoin.
	CurveSecp256k1 CurveType = "secp256k1"
	// CurveSecp256r1 is the P-256 curve for general ECDSA.
	CurveSecp256r1 CurveType = "secp256r1"
	// CurveEd25519 is the Ed25519 curve used by Solana and other systems.
	CurveEd25519 CurveType = "ed25519"
)

// IsValid checks if the curve type is valid.
func (c CurveType) IsValid() bool {
	switch c {
	case CurveSecp256k1, CurveSecp256r1, CurveEd25519:
		return true
	default:
		return false
	}
}

// Key represents a cryptographic key stored in Vault.
type Key struct {
	// InternalID is the system-generated unique identifier (UUID).
	InternalID string `json:"internal_id"`

	// Name is the user-provided name (required).
	Name string `json:"name"`

	// ExternalID is the user-provided external identifier (required, must be unique).
	ExternalID string `json:"external_id"`

	// Curve is the elliptic curve type used by this key.
	Curve CurveType `json:"curve"`

	// PrivateKey is the raw private key bytes (encrypted by Vault storage).
	// This field is NEVER returned to clients.
	PrivateKey []byte `json:"private_key"`

	// CreatedAt is the timestamp when the key was created.
	CreatedAt time.Time `json:"created_at"`

	// Metadata is optional user-defined key-value metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// KeyInfo is the key information returned to clients (without private key).
type KeyInfo struct {
	Name       string            `json:"name"`
	ExternalID string            `json:"external_id"`
	Curve      CurveType         `json:"curve"`
	PublicKey  string            `json:"public_key,omitempty"` // hex encoded
	CreatedAt  time.Time         `json:"created_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// ToInfo converts a Key to KeyInfo (strips private key).
func (k *Key) ToInfo() *KeyInfo {
	return &KeyInfo{
		Name:       k.Name,
		ExternalID: k.ExternalID,
		Curve:      k.Curve,
		CreatedAt:  k.CreatedAt,
		Metadata:   k.Metadata,
	}
}

// ToResponseData converts KeyInfo to a map for API response.
func (ki *KeyInfo) ToResponseData() map[string]interface{} {
	data := map[string]interface{}{
		"curve":      string(ki.Curve),
		"created_at": ki.CreatedAt.Format(time.RFC3339),
	}
	data["name"] = ki.Name
	data["external_id"] = ki.ExternalID
	data["public_key"] = ki.PublicKey
	data["metadata"] = ki.Metadata
	return data
}
