package vaultsdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestVault creates a mock Vault server and returns a configured client.
func newTestVault(t *testing.T, handler http.HandlerFunc) (Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client, srv
}

func TestCreateKey(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/crypto/keys") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Errorf("unexpected token: %s", r.Header.Get("X-Vault-Token"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
		}

		var body CreateKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body.Curve != "secp256k1" {
			t.Errorf("expected curve secp256k1, got %s", body.Curve)
		}
		if body.Name != "test-key" {
			t.Errorf("expected name test-key, got %s", body.Name)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"internal_id": "uuid-123",
				"name":        "test-key",
				"external_id": "",
				"curve":       "secp256k1",
				"public_key":  "0x04abcdef",
				"created_at":  "2024-01-01T00:00:00Z",
				"metadata":    nil,
			},
		})
	})

	key, err := client.CreateKey(context.Background(), &CreateKeyRequest{
		Curve: "secp256k1",
		Name:  "test-key",
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if key.InternalID != "uuid-123" {
		t.Errorf("expected internal_id uuid-123, got %s", key.InternalID)
	}
	if key.Curve != "secp256k1" {
		t.Errorf("expected curve secp256k1, got %s", key.Curve)
	}
	if key.PublicKey != "0x04abcdef" {
		t.Errorf("expected public_key 0x04abcdef, got %s", key.PublicKey)
	}
}

func TestListKeys(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Query().Get("list") != "true" {
			t.Errorf("expected list=true query param")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []string{"uuid-1", "uuid-2", "uuid-3"},
			},
		})
	})

	keys, err := client.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	if keys[0] != "uuid-1" || keys[1] != "uuid-2" || keys[2] != "uuid-3" {
		t.Errorf("unexpected keys: %v", keys)
	}
}

func TestListKeys_Empty(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		// Vault returns 404 when no keys exist.
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []string{},
		})
	})

	keys, err := client.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys (empty): %v", err)
	}
	if keys != nil {
		t.Errorf("expected nil, got %v", keys)
	}
}

func TestReadKey(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/crypto/keys/uuid-456") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"internal_id": "uuid-456",
				"name":        "my-key",
				"external_id": "ext-1",
				"curve":       "ed25519",
				"public_key":  "0xdeadbeef",
				"created_at":  "2024-06-15T12:00:00Z",
				"metadata":    map[string]string{"env": "prod"},
			},
		})
	})

	key, err := client.ReadKey(context.Background(), "uuid-456")
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if key.InternalID != "uuid-456" {
		t.Errorf("expected uuid-456, got %s", key.InternalID)
	}
	if key.Name != "my-key" {
		t.Errorf("expected my-key, got %s", key.Name)
	}
	if key.Metadata["env"] != "prod" {
		t.Errorf("expected metadata env=prod, got %v", key.Metadata)
	}
}

func TestSign(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/crypto/keys/uuid-789/sign") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var body SignRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if body.Data != "0xabcdef" {
			t.Errorf("expected data 0xabcdef, got %s", body.Data)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"signature":   "0xsig123",
				"curve":       "secp256k1",
				"internal_id": "uuid-789",
			},
		})
	})

	prehashed := true
	resp, err := client.Sign(context.Background(), "uuid-789", &SignRequest{
		Data:      "0xabcdef",
		Prehashed: &prehashed,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if resp.Signature != "0xsig123" {
		t.Errorf("expected signature 0xsig123, got %s", resp.Signature)
	}
	if resp.InternalID != "uuid-789" {
		t.Errorf("expected internal_id uuid-789, got %s", resp.InternalID)
	}
}

func TestSign_PrehashedFalse(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"prehashed":false`) {
			t.Errorf("expected prehashed=false in body, got %s", string(body))
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"signature":   "0xsig",
				"curve":       "secp256k1",
				"internal_id": "uuid-1",
			},
		})
	})

	prehashed := false
	_, err := client.Sign(context.Background(), "uuid-1", &SignRequest{
		Data:      "0xdeadbeef",
		Prehashed: &prehashed,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

func TestBuildEVMTransaction_Legacy(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/crypto/tx/build/evm") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var body BuildEVMTransactionRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if body.TxType != "legacy" {
			t.Errorf("expected tx_type legacy, got %s", body.TxType)
		}
		if body.ChainID != 11155111 {
			t.Errorf("expected chain_id 11155111, got %d", body.ChainID)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":         "0xabcdef1234567890",
				"prehashed":    true,
				"encoding":     "hex",
				"tx_type":      "legacy",
				"signing_hash": "0xabcdef1234567890",
			},
		})
	})

	resp, err := client.BuildEVMTransaction(context.Background(), &BuildEVMTransactionRequest{
		TxType:   "legacy",
		ChainID:  11155111,
		Nonce:    0,
		GasLimit: 21000,
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
		Value:    "1000000000000000",
		GasPrice: "10000000000",
	})
	if err != nil {
		t.Fatalf("BuildEVMTransaction: %v", err)
	}
	if resp.Data != "0xabcdef1234567890" {
		t.Errorf("expected data 0xabcdef1234567890, got %s", resp.Data)
	}
	if !resp.Prehashed {
		t.Error("expected prehashed=true")
	}
	if resp.TxType != "legacy" {
		t.Errorf("expected tx_type legacy, got %s", resp.TxType)
	}
}

func TestBuildEVMTransaction_EIP1559(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		var body BuildEVMTransactionRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if body.TxType != "eip1559" {
			t.Errorf("expected tx_type eip1559, got %s", body.TxType)
		}
		if body.MaxFeePerGas != "30000000000" {
			t.Errorf("expected max_fee_per_gas 30000000000, got %s", body.MaxFeePerGas)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":         "0x1234",
				"prehashed":    true,
				"encoding":     "hex",
				"tx_type":      "eip1559",
				"signing_hash": "0x1234",
			},
		})
	})

	resp, err := client.BuildEVMTransaction(context.Background(), &BuildEVMTransactionRequest{
		TxType:               "eip1559",
		ChainID:              1,
		Nonce:                5,
		GasLimit:             21000,
		To:                   "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
		Value:                "0",
		MaxFeePerGas:         "30000000000",
		MaxPriorityFeePerGas: "2000000000",
	})
	if err != nil {
		t.Fatalf("BuildEVMTransaction: %v", err)
	}
	if resp.TxType != "eip1559" {
		t.Errorf("expected tx_type eip1559, got %s", resp.TxType)
	}
}

func TestVaultError(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []string{"missing required field: curve"},
		})
	})

	_, err := client.CreateKey(context.Background(), &CreateKeyRequest{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var vaultErr *Error
	if !errors.As(err, &vaultErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if vaultErr.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", vaultErr.StatusCode)
	}
	if len(vaultErr.Errors) != 1 || vaultErr.Errors[0] != "missing required field: curve" {
		t.Errorf("unexpected errors: %v", vaultErr.Errors)
	}
}

func TestVaultError_NotFound(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []string{},
		})
	})

	_, err := client.ReadKey(context.Background(), "non-existent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var vaultErr *Error
	if !errors.As(err, &vaultErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if vaultErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", vaultErr.StatusCode)
	}
}

func TestCustomMountPath(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1/my-crypto/keys") {
			t.Errorf("expected mount path my-crypto, got path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []string{"uuid-1"},
			},
		})
	})

	// Re-create client with custom mount path. The newTestVault helper
	// uses default mount path, so we need to create a new one manually.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1/my-crypto/keys") {
			t.Errorf("expected mount path my-crypto, got path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []string{"uuid-1"},
			},
		})
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(srv.URL, "token", WithMountPath("my-crypto"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_ = client // suppress unused warning from first client
	keys, err := client.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
}

func TestTLSWithCACert(t *testing.T) {
	// Generate a self-signed CA certificate.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Generate a server certificate signed by the CA.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load server TLS cert: %v", err)
	}

	// Create TLS server.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []string{"tls-key-1"},
			},
		})
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// Test WithCAPEM.
	client, err := NewClient(srv.URL, "token", WithCAPEM(caPEM))
	if err != nil {
		t.Fatalf("NewClient with CAPem: %v", err)
	}

	keys, err := client.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys over TLS: %v", err)
	}
	if len(keys) != 1 || keys[0] != "tls-key-1" {
		t.Errorf("unexpected keys: %v", keys)
	}

	// Test WithCACert (file-based).
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o644); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	client2, err := NewClient(srv.URL, "token", WithCACert(caFile))
	if err != nil {
		t.Fatalf("NewClient with CACert: %v", err)
	}

	keys2, err := client2.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys over TLS (file): %v", err)
	}
	if len(keys2) != 1 || keys2[0] != "tls-key-1" {
		t.Errorf("unexpected keys: %v", keys2)
	}
}

func TestContextCancellation(t *testing.T) {
	client, _ := newTestVault(t, func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response; use the request context to detect cancellation.
		select {
		case <-r.Context().Done():
			return
		case <-time.After(10 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.ListKeys(ctx)
	if err == nil {
		t.Fatal("expected context deadline error, got nil")
	}
}

func TestNewClient_InvalidCACertPath(t *testing.T) {
	_, err := NewClient("https://vault.example.com", "token",
		WithCACert("/nonexistent/ca.pem"),
	)
	if err == nil {
		t.Fatal("expected error for nonexistent CA cert file")
	}
}

func TestErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      Error
		expected string
	}{
		{
			name:     "no errors",
			err:      Error{StatusCode: 500},
			expected: "vault: HTTP 500",
		},
		{
			name:     "single error",
			err:      Error{StatusCode: 400, Errors: []string{"bad request"}},
			expected: "vault: bad request (HTTP 400)",
		},
		{
			name:     "multiple errors",
			err:      Error{StatusCode: 400, Errors: []string{"err1", "err2"}},
			expected: "vault: [err1 err2] (HTTP 400)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
