// Package evmtx provides utilities for constructing EVM transaction signing
// data and converting secp256k1 public keys to Ethereum addresses.
//
// This package is designed to work with the Vault crypto plugin's keys and
// sign APIs. It supports Legacy (EIP-155) and EIP-1559 (dynamic fee)
// transaction types.
//
// Typical workflow:
//
//  1. Create a key via POST /keys {"curve": "secp256k1"}
//  2. Convert the returned public_key to an Ethereum address:
//     addr, _ := evmtx.PubKeyToChecksumAddress(publicKey)
//  3. Build a transaction and get its signing hash:
//     tx := &evmtx.LegacyTx{...}
//     req := evmtx.PrepareSignRequest(tx.SigningHash())
//  4. Call the sign API with req.Data and req.Prehashed
//  5. Assemble the signed transaction:
//     signedTx, _ := tx.AssembleSignedTx(signatureBytes)
//  6. Broadcast via eth_sendRawTransaction:
//     rawTxHex := evmtx.EncodeSignedTxForBroadcast(signedTx)
package evmtx

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

// ============================================================================
// Keccak256
// ============================================================================

// Keccak256 computes the Keccak-256 hash of the input data.
// Ethereum uses the original Keccak-256, NOT the NIST-standardized SHA3-256.
func Keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// ============================================================================
// Ethereum Address Derivation
// ============================================================================

// PubKeyToAddress converts an uncompressed secp256k1 public key (as returned
// by the plugin's keys API) to a lowercase Ethereum address.
//
// Input: "0x04..." hex string (65 bytes uncompressed public key).
// Output: "0x..." lowercase Ethereum address (42 chars).
func PubKeyToAddress(pubKeyHex string) (string, error) {
	pubBytes, err := decodeUncompressedPubKey(pubKeyHex)
	if err != nil {
		return "", err
	}
	// Keccak256 of the 64-byte X||Y (without the 0x04 prefix)
	hash := Keccak256(pubBytes[1:])
	// Take the last 20 bytes
	addr := hash[12:]
	return "0x" + hex.EncodeToString(addr), nil
}

// PubKeyToChecksumAddress converts an uncompressed secp256k1 public key to
// an EIP-55 checksum-encoded Ethereum address.
//
// Input: "0x04..." hex string (65 bytes uncompressed public key).
// Output: "0x..." mixed-case checksum address (42 chars).
func PubKeyToChecksumAddress(pubKeyHex string) (string, error) {
	pubBytes, err := decodeUncompressedPubKey(pubKeyHex)
	if err != nil {
		return "", err
	}
	hash := Keccak256(pubBytes[1:])
	addr := hash[12:]
	return "0x" + toChecksumAddress(hex.EncodeToString(addr)), nil
}

// decodeUncompressedPubKey parses and validates a hex-encoded uncompressed
// secp256k1 public key.
func decodeUncompressedPubKey(pubKeyHex string) ([]byte, error) {
	cleaned := strings.TrimPrefix(pubKeyHex, "0x")
	pubBytes, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid hex encoding: %w", err)
	}
	if len(pubBytes) != 65 {
		return nil, fmt.Errorf("expected 65-byte uncompressed public key, got %d bytes", len(pubBytes))
	}
	if pubBytes[0] != 0x04 {
		return nil, fmt.Errorf("expected uncompressed public key prefix 0x04, got 0x%02x", pubBytes[0])
	}
	return pubBytes, nil
}

// toChecksumAddress applies EIP-55 mixed-case checksum encoding.
// Input: 40-char lowercase hex address (without "0x" prefix).
func toChecksumAddress(address string) string {
	address = strings.ToLower(address)
	hash := Keccak256([]byte(address))
	result := make([]byte, len(address))
	for i, c := range address {
		if c >= '0' && c <= '9' {
			result[i] = byte(c)
		} else {
			// Get the corresponding nibble from the hash
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

// ============================================================================
// RLP Encoding (minimal, encode-only implementation)
// ============================================================================

// RLPItem is the interface for types that can be RLP-encoded.
type RLPItem interface {
	rlpEncode() []byte
}

// RLPBytes represents a byte string for RLP encoding.
type RLPBytes []byte

func (b RLPBytes) rlpEncode() []byte {
	length := len(b)
	if length == 1 && b[0] <= 0x7f {
		return []byte{b[0]}
	}
	if length <= 55 {
		result := make([]byte, 1+length)
		result[0] = 0x80 + byte(length)
		copy(result[1:], b)
		return result
	}
	lenBytes := encodeBigEndian(uint64(length))
	result := make([]byte, 1+len(lenBytes)+length)
	result[0] = 0xb7 + byte(len(lenBytes))
	copy(result[1:], lenBytes)
	copy(result[1+len(lenBytes):], b)
	return result
}

// RLPList represents a list of RLP items.
type RLPList []RLPItem

func (l RLPList) rlpEncode() []byte {
	var payload []byte
	for _, item := range l {
		payload = append(payload, item.rlpEncode()...)
	}
	length := len(payload)
	if length <= 55 {
		result := make([]byte, 1+length)
		result[0] = 0xc0 + byte(length)
		copy(result[1:], payload)
		return result
	}
	lenBytes := encodeBigEndian(uint64(length))
	result := make([]byte, 1+len(lenBytes)+length)
	result[0] = 0xf7 + byte(len(lenBytes))
	copy(result[1:], lenBytes)
	copy(result[1+len(lenBytes):], payload)
	return result
}

// RLPBigInt converts a *big.Int to RLPBytes suitable for RLP encoding.
// nil and zero are encoded as empty byte string.
func RLPBigInt(v *big.Int) RLPBytes {
	if v == nil || v.Sign() == 0 {
		return RLPBytes{}
	}
	return RLPBytes(v.Bytes())
}

// RLPUint64 converts a uint64 to RLPBytes suitable for RLP encoding.
// Zero is encoded as empty byte string.
func RLPUint64(v uint64) RLPBytes {
	if v == 0 {
		return RLPBytes{}
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	// Strip leading zeros
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	return RLPBytes(buf)
}

// EncodeRLP encodes an RLPItem and returns the raw bytes.
func EncodeRLP(item RLPItem) []byte {
	return item.rlpEncode()
}

// encodeBigEndian encodes a uint64 as big-endian bytes with no leading zeros.
func encodeBigEndian(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	return buf
}

// ============================================================================
// Transaction Types
// ============================================================================

// LegacyTx represents an EIP-155 legacy transaction.
type LegacyTx struct {
	Nonce    uint64
	GasPrice *big.Int
	GasLimit uint64
	To       *[20]byte // nil for contract creation
	Value    *big.Int
	Data     []byte
	ChainID  *big.Int
}

// SigningHash returns the Keccak256 hash of the RLP-encoded transaction for
// signing, following EIP-155.
//
// Hash = Keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))
func (tx *LegacyTx) SigningHash() []byte {
	return Keccak256(tx.rlpForSigning())
}

func (tx *LegacyTx) rlpForSigning() []byte {
	items := RLPList{
		RLPUint64(tx.Nonce),
		RLPBigInt(tx.GasPrice),
		RLPUint64(tx.GasLimit),
		rlpAddress(tx.To),
		RLPBigInt(tx.Value),
		RLPBytes(tx.Data),
		RLPBigInt(tx.ChainID),
		RLPUint64(0), // EIP-155: empty r
		RLPUint64(0), // EIP-155: empty s
	}
	return EncodeRLP(items)
}

// AssembleSignedTx takes a 65-byte signature (R||S||V) from the plugin and
// returns the fully serialized signed legacy transaction.
//
// The plugin returns V as 0 or 1. For EIP-155, V is adjusted to:
//
//	v = chainId * 2 + 35 + recoveryId
//
// Output: RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
func (tx *LegacyTx) AssembleSignedTx(signature []byte) ([]byte, error) {
	r, s, v, err := splitSignature(signature)
	if err != nil {
		return nil, err
	}

	// EIP-155 V adjustment: v = chainId * 2 + 35 + recoveryId
	bigV := new(big.Int)
	if tx.ChainID != nil {
		bigV.Mul(tx.ChainID, big.NewInt(2))
		bigV.Add(bigV, big.NewInt(35))
		bigV.Add(bigV, new(big.Int).SetUint64(uint64(v)))
	} else {
		bigV.SetUint64(uint64(v) + 27)
	}

	items := RLPList{
		RLPUint64(tx.Nonce),
		RLPBigInt(tx.GasPrice),
		RLPUint64(tx.GasLimit),
		rlpAddress(tx.To),
		RLPBigInt(tx.Value),
		RLPBytes(tx.Data),
		RLPBigInt(bigV),
		RLPBigInt(r),
		RLPBigInt(s),
	}
	return EncodeRLP(items), nil
}

// AccessTuple represents an access list entry per EIP-2930.
type AccessTuple struct {
	Address     [20]byte
	StorageKeys [][32]byte
}

// DynamicFeeTx represents an EIP-1559 dynamic fee transaction (type 0x02).
type DynamicFeeTx struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	GasLimit             uint64
	To                   *[20]byte // nil for contract creation
	Value                *big.Int
	Data                 []byte
	AccessList           []AccessTuple
}

// SigningHash returns the Keccak256 hash for signing an EIP-1559 transaction.
//
// Hash = Keccak256(0x02 || RLP([chainId, nonce, maxPriorityFeePerGas,
// maxFeePerGas, gasLimit, to, value, data, accessList]))
func (tx *DynamicFeeTx) SigningHash() []byte {
	payload := tx.rlpForSigning()
	// Prepend type byte 0x02
	typed := make([]byte, 1+len(payload))
	typed[0] = 0x02
	copy(typed[1:], payload)
	return Keccak256(typed)
}

func (tx *DynamicFeeTx) rlpForSigning() []byte {
	items := RLPList{
		RLPBigInt(tx.ChainID),
		RLPUint64(tx.Nonce),
		RLPBigInt(tx.MaxPriorityFeePerGas),
		RLPBigInt(tx.MaxFeePerGas),
		RLPUint64(tx.GasLimit),
		rlpAddress(tx.To),
		RLPBigInt(tx.Value),
		RLPBytes(tx.Data),
		rlpAccessList(tx.AccessList),
	}
	return EncodeRLP(items)
}

// AssembleSignedTx takes a 65-byte signature (R||S||V) from the plugin and
// returns the fully serialized signed EIP-1559 transaction.
//
// For EIP-1559, V is the recovery id (0 or 1) without chain ID adjustment.
//
// Output: 0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
// gasLimit, to, value, data, accessList, v, r, s])
func (tx *DynamicFeeTx) AssembleSignedTx(signature []byte) ([]byte, error) {
	r, s, v, err := splitSignature(signature)
	if err != nil {
		return nil, err
	}

	items := RLPList{
		RLPBigInt(tx.ChainID),
		RLPUint64(tx.Nonce),
		RLPBigInt(tx.MaxPriorityFeePerGas),
		RLPBigInt(tx.MaxFeePerGas),
		RLPUint64(tx.GasLimit),
		rlpAddress(tx.To),
		RLPBigInt(tx.Value),
		RLPBytes(tx.Data),
		rlpAccessList(tx.AccessList),
		RLPUint64(uint64(v)),
		RLPBigInt(r),
		RLPBigInt(s),
	}
	payload := EncodeRLP(items)

	// Prepend type byte 0x02
	result := make([]byte, 1+len(payload))
	result[0] = 0x02
	copy(result[1:], payload)
	return result, nil
}

// ============================================================================
// Signing Workflow Helpers
// ============================================================================

// SignRequest represents the data needed to call the Vault plugin's sign API.
type SignRequest struct {
	// Data is the hex-encoded hash to sign (with "0x" prefix).
	Data string `json:"data"`
	// Prehashed indicates the data is already hashed (always true for EVM tx).
	Prehashed bool `json:"prehashed"`
	// Encoding is the input data encoding format.
	Encoding string `json:"encoding"`
}

// PrepareSignRequest constructs a SignRequest from a transaction's signing hash.
// The returned Data field is the hex-encoded Keccak256 hash ready to pass to
// the plugin's /keys/:id/sign endpoint.
func PrepareSignRequest(signingHash []byte) *SignRequest {
	return &SignRequest{
		Data:      "0x" + hex.EncodeToString(signingHash),
		Prehashed: true,
		Encoding:  "hex",
	}
}

// ParseSignature parses a hex-encoded signature from the plugin's sign API
// response into raw 65 bytes (R || S || V).
func ParseSignature(signatureHex string) ([]byte, error) {
	cleaned := strings.TrimPrefix(signatureHex, "0x")
	sigBytes, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(sigBytes) != 65 {
		return nil, fmt.Errorf("expected 65-byte signature, got %d bytes", len(sigBytes))
	}
	if sigBytes[64] > 1 {
		return nil, fmt.Errorf("invalid recovery id %d, expected 0 or 1", sigBytes[64])
	}
	return sigBytes, nil
}

// EncodeSignedTxForBroadcast takes raw signed transaction bytes and returns
// the hex string with "0x" prefix suitable for eth_sendRawTransaction.
func EncodeSignedTxForBroadcast(signedTx []byte) string {
	return "0x" + hex.EncodeToString(signedTx)
}

// ============================================================================
// Internal helpers
// ============================================================================

// rlpAddress encodes an address for RLP. nil means contract creation (empty bytes).
func rlpAddress(addr *[20]byte) RLPBytes {
	if addr == nil {
		return RLPBytes{}
	}
	return RLPBytes(addr[:])
}

// rlpAccessList encodes an access list for RLP.
func rlpAccessList(accessList []AccessTuple) RLPList {
	list := make(RLPList, len(accessList))
	for i, tuple := range accessList {
		keys := make(RLPList, len(tuple.StorageKeys))
		for j, key := range tuple.StorageKeys {
			keys[j] = RLPBytes(key[:])
		}
		list[i] = RLPList{
			RLPBytes(tuple.Address[:]),
			keys,
		}
	}
	return list
}

// splitSignature splits a 65-byte signature into R, S (*big.Int) and V (byte).
func splitSignature(sig []byte) (r, s *big.Int, v byte, err error) {
	if len(sig) != 65 {
		return nil, nil, 0, fmt.Errorf("expected 65-byte signature, got %d bytes", len(sig))
	}
	r = new(big.Int).SetBytes(sig[0:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = sig[64]
	if v > 1 {
		return nil, nil, 0, fmt.Errorf("invalid recovery id %d, expected 0 or 1", v)
	}
	return r, s, v, nil
}

// ParseHex decodes a hex string (without "0x" prefix) into bytes.
func ParseHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
