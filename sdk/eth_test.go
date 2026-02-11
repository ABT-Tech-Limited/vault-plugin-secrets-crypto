package vaultsdk

import (
	"strings"
	"testing"
)

func TestPubKeyToETHChecksumAddress(t *testing.T) {
	pubKey := "0x04aa7ef0388195609f3204a8ad148d147eb6d3f360b0a3ec4d1971db9e163ca66e2c4c42240614ec5645e37724445063c80ce490a3a77c90be26c7332c786c694d"
	addr, err := PubKeyToETHChecksumAddress(pubKey)
	if err != nil {
		t.Fatalf("PubKeyToETHChecksumAddress error: %v", err)
	}
	want := "0x5e6746671c75F2508a4dD40DcFda4729b6c61931"
	if addr != want {
		t.Errorf("got %s, want %s", addr, want)
	}
}

func TestPubKeyToETHChecksumAddress_InvalidInput(t *testing.T) {
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
			_, err := PubKeyToETHChecksumAddress(tt.input)
			if err == nil {
				t.Errorf("expected error for input %s", tt.input)
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestKey_ETHChecksumAddress(t *testing.T) {
	key := &Key{
		Curve:     "secp256k1",
		PublicKey: "0x04aa7ef0388195609f3204a8ad148d147eb6d3f360b0a3ec4d1971db9e163ca66e2c4c42240614ec5645e37724445063c80ce490a3a77c90be26c7332c786c694d",
	}
	addr, err := key.ETHChecksumAddress()
	if err != nil {
		t.Fatalf("ETHChecksumAddress error: %v", err)
	}
	want := "0x5e6746671c75F2508a4dD40DcFda4729b6c61931"
	if addr != want {
		t.Errorf("got %s, want %s", addr, want)
	}
}

func TestKey_ETHChecksumAddress_WrongCurve(t *testing.T) {
	key := &Key{
		Curve:     "ed25519",
		PublicKey: "0xdeadbeef",
	}
	_, err := key.ETHChecksumAddress()
	if err == nil {
		t.Fatal("expected error for non-secp256k1 curve")
	}
	if !strings.Contains(err.Error(), "secp256k1") {
		t.Errorf("expected error mentioning secp256k1, got %q", err.Error())
	}
}
