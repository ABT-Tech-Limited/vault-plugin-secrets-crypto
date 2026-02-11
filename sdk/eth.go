package vaultsdk

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

// ETHChecksumAddress derives the EIP-55 checksum Ethereum address from the
// key's secp256k1 public key.
//
// Returns an error if the key's curve is not secp256k1 or the public key
// format is invalid.
func (k *Key) ETHChecksumAddress() (string, error) {
	if k.Curve != "secp256k1" {
		return "", fmt.Errorf("ETH address derivation requires secp256k1 curve, got %s", k.Curve)
	}
	return PubKeyToETHChecksumAddress(k.PublicKey)
}

// PubKeyToETHChecksumAddress converts an uncompressed secp256k1 public key
// (hex-encoded, "0x04..." format) to an EIP-55 checksum Ethereum address.
func PubKeyToETHChecksumAddress(pubKeyHex string) (string, error) {
	cleaned := strings.TrimPrefix(pubKeyHex, "0x")
	pubBytes, err := hex.DecodeString(cleaned)
	if err != nil {
		return "", fmt.Errorf("invalid hex encoding: %w", err)
	}
	if len(pubBytes) != 65 {
		return "", fmt.Errorf("expected 65-byte uncompressed public key, got %d bytes", len(pubBytes))
	}
	if pubBytes[0] != 0x04 {
		return "", fmt.Errorf("expected uncompressed public key prefix 0x04, got 0x%02x", pubBytes[0])
	}

	// Keccak256 of the 64-byte X||Y (without the 0x04 prefix)
	hash := keccak256(pubBytes[1:])
	// Take the last 20 bytes as the address
	addr := hash[12:]
	return "0x" + toChecksumAddress(hex.EncodeToString(addr)), nil
}

// keccak256 computes the Keccak-256 hash (Ethereum uses the original
// Keccak-256, NOT the NIST-standardized SHA3-256).
func keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// toChecksumAddress applies EIP-55 mixed-case checksum encoding.
// Input: 40-char lowercase hex address (without "0x" prefix).
func toChecksumAddress(address string) string {
	address = strings.ToLower(address)
	hash := keccak256([]byte(address))
	result := make([]byte, len(address))
	for i, c := range address {
		if c >= '0' && c <= '9' {
			result[i] = byte(c)
		} else {
			hashByte := hash[i/2]
			var nibble byte
			if i%2 == 0 {
				nibble = hashByte >> 4
			} else {
				nibble = hashByte & 0x0f
			}
			if nibble >= 8 {
				result[i] = byte(c) - 32 // uppercase
			} else {
				result[i] = byte(c)
			}
		}
	}
	return string(result)
}
