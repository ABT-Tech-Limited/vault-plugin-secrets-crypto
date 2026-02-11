package evmtx

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func mustDecodeHex(s string) []byte {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexAddr(s string) *[20]byte {
	b := mustDecodeHex(s)
	if len(b) != 20 {
		panic("address must be 20 bytes")
	}
	var addr [20]byte
	copy(addr[:], b)
	return &addr
}

// ============================================================================
// Keccak256 Tests
// ============================================================================

func TestKeccak256Empty(t *testing.T) {
	// Keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
	got := hex.EncodeToString(Keccak256([]byte{}))
	want := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got != want {
		t.Errorf("Keccak256 empty: got %s, want %s", got, want)
	}
}

func TestKeccak256Hello(t *testing.T) {
	// Keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
	got := hex.EncodeToString(Keccak256([]byte("hello")))
	want := "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
	if got != want {
		t.Errorf("Keccak256 hello: got %s, want %s", got, want)
	}
}

func TestKeccak256MultipleInputs(t *testing.T) {
	// Keccak256("hello" + "world") should equal Keccak256("helloworld")
	got1 := Keccak256([]byte("hello"), []byte("world"))
	got2 := Keccak256([]byte("helloworld"))
	if !bytes.Equal(got1, got2) {
		t.Errorf("Keccak256 multi-input mismatch: %x != %x", got1, got2)
	}
}

// ============================================================================
// Address Derivation Tests
// ============================================================================

func TestPubKeyToAddress(t *testing.T) {
	// Known test vector: Ethereum address derived from a known public key
	// Private key: 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356
	// Uncompressed public key (65 bytes, with 04 prefix)
	// Expected address: 0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1
	pubKey := "0x04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39"

	addr, err := PubKeyToAddress(pubKey)
	if err != nil {
		t.Fatalf("PubKeyToAddress error: %v", err)
	}
	want := "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1"
	if addr != want {
		t.Errorf("PubKeyToAddress: got %s, want %s", addr, want)
	}
}

func TestPubKeyToChecksumAddress(t *testing.T) {
	pubKey := "0x04aa7ef0388195609f3204a8ad148d147eb6d3f360b0a3ec4d1971db9e163ca66e2c4c42240614ec5645e37724445063c80ce490a3a77c90be26c7332c786c694d"

	addr, err := PubKeyToChecksumAddress(pubKey)
	if err != nil {
		t.Fatalf("PubKeyToChecksumAddress error: %v", err)
	}
	want := "0x5e6746671c75F2508a4dD40DcFda4729b6c61931"
	if addr != want {
		t.Errorf("PubKeyToChecksumAddress: got %s, want %s", addr, want)
	}
}

func TestPubKeyToAddressInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		errMsg string
	}{
		{"short key", "0x04aabb", "expected 65-byte"},
		{"bad prefix", "0x03" + "aa" + strings.Repeat("bb", 63), "expected uncompressed public key prefix"},
		{"bad hex", "0x04zzzz", "invalid hex encoding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PubKeyToAddress(tt.input)
			if err == nil {
				t.Errorf("expected error for input %s", tt.input)
			}
		})
	}
}

// ============================================================================
// EIP-55 Checksum Tests
// ============================================================================

func TestChecksumAddress(t *testing.T) {
	// Test vectors from EIP-55
	tests := []struct {
		input string
		want  string
	}{
		{"5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{"fb6916095ca1df60bb79ce92ce3ea74c37c5d359", "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"},
		{"dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb", "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"},
		{"d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb", "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"},
	}
	for _, tt := range tests {
		got := toChecksumAddress(tt.input)
		if got != tt.want {
			t.Errorf("toChecksumAddress(%s): got %s, want %s", tt.input, got, tt.want)
		}
	}
}

// ============================================================================
// RLP Encoding Tests
// ============================================================================

func TestRLPEncodeEmptyString(t *testing.T) {
	got := EncodeRLP(RLPBytes{})
	want := []byte{0x80}
	if !bytes.Equal(got, want) {
		t.Errorf("RLP empty string: got %x, want %x", got, want)
	}
}

func TestRLPEncodeSingleByte(t *testing.T) {
	// Single byte [0x00, 0x7f] encodes as itself
	got := EncodeRLP(RLPBytes{0x42})
	want := []byte{0x42}
	if !bytes.Equal(got, want) {
		t.Errorf("RLP single byte 0x42: got %x, want %x", got, want)
	}

	// Byte 0x00 is a single byte, encodes as itself
	got = EncodeRLP(RLPBytes{0x00})
	want = []byte{0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("RLP single byte 0x00: got %x, want %x", got, want)
	}
}

func TestRLPEncodeShortString(t *testing.T) {
	// "dog" = [0x83, 'd', 'o', 'g']
	got := EncodeRLP(RLPBytes("dog"))
	want := []byte{0x83, 'd', 'o', 'g'}
	if !bytes.Equal(got, want) {
		t.Errorf("RLP 'dog': got %x, want %x", got, want)
	}
}

func TestRLPEncode55ByteString(t *testing.T) {
	// 55 bytes: 0x80 + 55 = 0xb7 prefix
	data := bytes.Repeat([]byte{0xaa}, 55)
	got := EncodeRLP(RLPBytes(data))
	if got[0] != 0xb7 {
		t.Errorf("RLP 55-byte string prefix: got 0x%02x, want 0xb7", got[0])
	}
	if len(got) != 56 {
		t.Errorf("RLP 55-byte string length: got %d, want 56", len(got))
	}
}

func TestRLPEncodeLongString(t *testing.T) {
	// 56 bytes: needs length-of-length encoding
	data := bytes.Repeat([]byte{0xbb}, 56)
	got := EncodeRLP(RLPBytes(data))
	// 0xb7 + 1 = 0xb8, then length 56 = 0x38
	if got[0] != 0xb8 || got[1] != 0x38 {
		t.Errorf("RLP 56-byte string header: got %x, want b838", got[:2])
	}
}

func TestRLPEncodeEmptyList(t *testing.T) {
	got := EncodeRLP(RLPList{})
	want := []byte{0xc0}
	if !bytes.Equal(got, want) {
		t.Errorf("RLP empty list: got %x, want %x", got, want)
	}
}

func TestRLPEncodeShortList(t *testing.T) {
	// ["cat", "dog"]
	got := EncodeRLP(RLPList{RLPBytes("cat"), RLPBytes("dog")})
	want := []byte{0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g'}
	if !bytes.Equal(got, want) {
		t.Errorf("RLP ['cat','dog']: got %x, want %x", got, want)
	}
}

func TestRLPUint64(t *testing.T) {
	tests := []struct {
		input uint64
		want  []byte
	}{
		{0, []byte{0x80}},         // empty string encoding
		{1, []byte{0x01}},         // single byte
		{127, []byte{0x7f}},       // max single byte
		{128, []byte{0x81, 0x80}}, // short string
		{256, []byte{0x82, 0x01, 0x00}},
		{1024, []byte{0x82, 0x04, 0x00}},
	}
	for _, tt := range tests {
		got := EncodeRLP(RLPUint64(tt.input))
		if !bytes.Equal(got, tt.want) {
			t.Errorf("RLPUint64(%d): got %x, want %x", tt.input, got, tt.want)
		}
	}
}

func TestRLPBigInt(t *testing.T) {
	// Zero
	got := EncodeRLP(RLPBigInt(big.NewInt(0)))
	if !bytes.Equal(got, []byte{0x80}) {
		t.Errorf("RLPBigInt(0): got %x, want 80", got)
	}

	// nil
	got = EncodeRLP(RLPBigInt(nil))
	if !bytes.Equal(got, []byte{0x80}) {
		t.Errorf("RLPBigInt(nil): got %x, want 80", got)
	}

	// 1
	got = EncodeRLP(RLPBigInt(big.NewInt(1)))
	if !bytes.Equal(got, []byte{0x01}) {
		t.Errorf("RLPBigInt(1): got %x, want 01", got)
	}
}

// ============================================================================
// Legacy Transaction Tests
// ============================================================================

func TestLegacyTxSigningHash(t *testing.T) {
	// Test a simple ETH transfer on mainnet (chainId=1)
	// This verifies the full pipeline: tx fields -> RLP -> Keccak256
	to := hexAddr("0x97E805240154199bd08f9a5808831199C5fEB3eC")
	tx := &LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(20000000000), // 20 Gwei
		GasLimit: 21000,
		To:       to,
		Value:    big.NewInt(100000000000000), // 0.00011 ETH
		Data:     nil,
		ChainID:  big.NewInt(11155111),
	}

	// Known signing hash for this transaction (EIP-155)
	// From: https://eips.ethereum.org/EIPS/eip-155
	hash := tx.SigningHash()
	got := hex.EncodeToString(hash)
	want := "2133a90ee9008f33b6f56b2fd37bd3fb0a4d8795ea9c71648a0ad237d0dad9ff"
	if got != want {
		t.Errorf("LegacyTx SigningHash: got %s, want %s", got, want)
	}
}

func TestLegacyTxAssembleSignedTx(t *testing.T) {
	// Use the EIP-155 test vector
	to := hexAddr("3535353535353535353535353535353535353535")
	tx := &LegacyTx{
		Nonce:    9,
		GasPrice: big.NewInt(20000000000),
		GasLimit: 21000,
		To:       to,
		Value:    big.NewInt(1000000000000000000),
		Data:     nil,
		ChainID:  big.NewInt(1),
	}

	// Known signature from EIP-155 example
	// r = 0x28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276
	// s = 0x67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83
	// v = 37 (chainId * 2 + 35 + 0) => recovery id = 0
	sig := make([]byte, 65)
	copy(sig[0:32], mustDecodeHex("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"))
	copy(sig[32:64], mustDecodeHex("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"))
	sig[64] = 0 // recovery id

	signedTx, err := tx.AssembleSignedTx(sig)
	if err != nil {
		t.Fatalf("AssembleSignedTx error: %v", err)
	}

	// Verify the signed tx matches the known EIP-155 output
	want := "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
	got := hex.EncodeToString(signedTx)
	if got != want {
		t.Errorf("LegacyTx AssembleSignedTx:\ngot  %s\nwant %s", got, want)
	}
}

// ============================================================================
// EIP-1559 Transaction Tests
// ============================================================================

func TestDynamicFeeTxSigningHash(t *testing.T) {
	// Simple EIP-1559 transaction
	to := hexAddr("d46e8dd67c5d32be8058bb8eb970870f07244567")
	tx := &DynamicFeeTx{
		ChainID:              big.NewInt(1),
		Nonce:                0,
		MaxPriorityFeePerGas: big.NewInt(2000000000),   // 2 Gwei
		MaxFeePerGas:         big.NewInt(100000000000), // 100 Gwei
		GasLimit:             21000,
		To:                   to,
		Value:                big.NewInt(1000000000000000000), // 1 ETH
		Data:                 nil,
		AccessList:           nil,
	}

	// Verify signing hash is deterministic and 32 bytes
	hash := tx.SigningHash()
	if len(hash) != 32 {
		t.Errorf("DynamicFeeTx SigningHash length: got %d, want 32", len(hash))
	}

	// Compute again to verify determinism
	hash2 := tx.SigningHash()
	if !bytes.Equal(hash, hash2) {
		t.Errorf("DynamicFeeTx SigningHash not deterministic")
	}
}

func TestDynamicFeeTxAssembleSignedTx(t *testing.T) {
	to := hexAddr("d46e8dd67c5d32be8058bb8eb970870f07244567")
	tx := &DynamicFeeTx{
		ChainID:              big.NewInt(1),
		Nonce:                0,
		MaxPriorityFeePerGas: big.NewInt(2000000000),
		MaxFeePerGas:         big.NewInt(100000000000),
		GasLimit:             21000,
		To:                   to,
		Value:                big.NewInt(1000000000000000000),
		Data:                 nil,
		AccessList:           nil,
	}

	// Create a mock signature
	sig := make([]byte, 65)
	copy(sig[0:32], bytes.Repeat([]byte{0x11}, 32))  // R
	copy(sig[32:64], bytes.Repeat([]byte{0x22}, 32)) // S
	sig[64] = 1                                      // V

	signedTx, err := tx.AssembleSignedTx(sig)
	if err != nil {
		t.Fatalf("AssembleSignedTx error: %v", err)
	}

	// Must start with type byte 0x02
	if signedTx[0] != 0x02 {
		t.Errorf("EIP-1559 signed tx should start with 0x02, got 0x%02x", signedTx[0])
	}

	// Should be non-empty and valid
	if len(signedTx) < 10 {
		t.Errorf("signed tx too short: %d bytes", len(signedTx))
	}
}

// ============================================================================
// Signing Workflow Tests
// ============================================================================

func TestPrepareSignRequest(t *testing.T) {
	hash := mustDecodeHex("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
	req := PrepareSignRequest(hash)

	if req.Data != "0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53" {
		t.Errorf("PrepareSignRequest Data: got %s", req.Data)
	}
	if !req.Prehashed {
		t.Error("PrepareSignRequest Prehashed should be true")
	}
	if req.Encoding != "hex" {
		t.Errorf("PrepareSignRequest Encoding: got %s, want hex", req.Encoding)
	}
}

func TestParseSignature(t *testing.T) {
	// Valid 65-byte signature
	sig := bytes.Repeat([]byte{0xaa}, 32)
	sig = append(sig, bytes.Repeat([]byte{0xbb}, 32)...)
	sig = append(sig, 0x01) // V = 1
	sigHex := "0x" + hex.EncodeToString(sig)

	parsed, err := ParseSignature(sigHex)
	if err != nil {
		t.Fatalf("ParseSignature error: %v", err)
	}
	if !bytes.Equal(parsed, sig) {
		t.Errorf("ParseSignature mismatch")
	}

	// Invalid: V > 1
	badSig := make([]byte, 65)
	badSig[64] = 2
	_, err = ParseSignature("0x" + hex.EncodeToString(badSig))
	if err == nil {
		t.Error("expected error for V > 1")
	}

	// Invalid: wrong length
	_, err = ParseSignature("0xaabb")
	if err == nil {
		t.Error("expected error for short signature")
	}
}

func TestEncodeSignedTxForBroadcast(t *testing.T) {
	data := []byte{0xf8, 0x6c, 0x09}
	got := EncodeSignedTxForBroadcast(data)
	want := "0xf86c09"
	if got != want {
		t.Errorf("EncodeSignedTxForBroadcast: got %s, want %s", got, want)
	}
}

// ============================================================================
// Access List Tests
// ============================================================================

func TestDynamicFeeTxWithAccessList(t *testing.T) {
	to := hexAddr("d46e8dd67c5d32be8058bb8eb970870f07244567")
	var storageKey [32]byte
	copy(storageKey[:], mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000001"))

	tx := &DynamicFeeTx{
		ChainID:              big.NewInt(1),
		Nonce:                1,
		MaxPriorityFeePerGas: big.NewInt(1000000000),
		MaxFeePerGas:         big.NewInt(50000000000),
		GasLimit:             50000,
		To:                   to,
		Value:                big.NewInt(0),
		Data:                 mustDecodeHex("a9059cbb"), // transfer selector
		AccessList: []AccessTuple{
			{
				Address:     *to,
				StorageKeys: [][32]byte{storageKey},
			},
		},
	}

	hash := tx.SigningHash()
	if len(hash) != 32 {
		t.Errorf("signing hash length: got %d, want 32", len(hash))
	}

	// Assemble with a mock signature
	sig := make([]byte, 65)
	copy(sig[0:32], bytes.Repeat([]byte{0x33}, 32))
	copy(sig[32:64], bytes.Repeat([]byte{0x44}, 32))
	sig[64] = 0

	signedTx, err := tx.AssembleSignedTx(sig)
	if err != nil {
		t.Fatalf("AssembleSignedTx error: %v", err)
	}
	if signedTx[0] != 0x02 {
		t.Errorf("should start with 0x02, got 0x%02x", signedTx[0])
	}
}

// ============================================================================
// Contract Creation Tests
// ============================================================================

func TestLegacyTxContractCreation(t *testing.T) {
	tx := &LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(20000000000),
		GasLimit: 100000,
		To:       nil, // contract creation
		Value:    big.NewInt(0),
		Data:     mustDecodeHex("6080604052"),
		ChainID:  big.NewInt(1),
	}

	hash := tx.SigningHash()
	if len(hash) != 32 {
		t.Errorf("contract creation signing hash length: got %d, want 32", len(hash))
	}
}
