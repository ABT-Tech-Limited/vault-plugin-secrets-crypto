package vaultsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// httpClient is the concrete implementation of the Client interface.
type httpClient struct {
	addr       string
	token      string
	mountPath  string
	httpClient *http.Client
}

// Compile-time check that httpClient implements Client.
var _ Client = (*httpClient)(nil)

// NewClient creates a new Vault crypto plugin client.
//
// addr is the Vault server address (e.g., "https://vault.example.com:8200").
// token is the Vault authentication token.
func NewClient(addr, token string, opts ...Option) (Client, error) {
	c := &httpClient{
		addr:      strings.TrimRight(addr, "/"),
		token:     token,
		mountPath: "crypto",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	cfg := &options{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("vaultsdk: option error: %w", err)
		}
	}

	if cfg.mountPath != "" {
		c.mountPath = cfg.mountPath
	}

	if cfg.httpClient != nil {
		c.httpClient = cfg.httpClient
	} else {
		if cfg.timeout > 0 {
			c.httpClient.Timeout = cfg.timeout
		}
		if cfg.tlsConfig != nil {
			c.httpClient.Transport = &http.Transport{
				TLSClientConfig: cfg.tlsConfig,
			}
		}
	}

	return c, nil
}

func (c *httpClient) baseURL() string {
	return c.addr + "/v1/" + c.mountPath
}

// CreateKey creates a new cryptographic key pair.
func (c *httpClient) CreateKey(ctx context.Context, req *CreateKeyRequest) (*Key, error) {
	resp, err := c.do(ctx, http.MethodPost, "/keys", req)
	if err != nil {
		return nil, err
	}
	var key Key
	if err := c.parseResponse(resp, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// ListKeys returns a list of all key external IDs.
func (c *httpClient) ListKeys(ctx context.Context) ([]string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/keys?list=true", nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Keys []string `json:"keys"`
	}
	if err := c.parseResponse(resp, &result); err != nil {
		// Vault returns 404 when there are no keys.
		var vaultErr *Error
		if errors.As(err, &vaultErr) && vaultErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return result.Keys, nil
}

// ReadKey retrieves key information by its external ID.
func (c *httpClient) ReadKey(ctx context.Context, externalID string) (*Key, error) {
	resp, err := c.do(ctx, http.MethodGet, "/keys/"+externalID, nil)
	if err != nil {
		return nil, err
	}
	var key Key
	if err := c.parseResponse(resp, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// Sign signs data with the specified key.
func (c *httpClient) Sign(ctx context.Context, externalID string, req *SignRequest) (*SignResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/keys/"+externalID+"/sign", req)
	if err != nil {
		return nil, err
	}
	var result SignResponse
	if err := c.parseResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BuildEVMTransaction builds EVM transaction signing data.
func (c *httpClient) BuildEVMTransaction(ctx context.Context, req *BuildEVMTransactionRequest) (*BuildEVMTransactionResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/tx/build/evm", req)
	if err != nil {
		return nil, err
	}
	var result BuildEVMTransactionResponse
	if err := c.parseResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// do executes an HTTP request with the Vault token header.
func (c *httpClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	url := c.baseURL() + path

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.httpClient.Do(req)
}

// parseResponse reads the HTTP response body, checks for errors, and
// unmarshals the Vault response envelope's "data" field into v.
func (c *httpClient) parseResponse(resp *http.Response, v any) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []string        `json:"errors"`
	}

	if err := json.Unmarshal(body, &envelope); err != nil {
		if resp.StatusCode != http.StatusOK {
			return &Error{StatusCode: resp.StatusCode}
		}
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if resp.StatusCode != http.StatusOK || len(envelope.Errors) > 0 {
		return &Error{
			StatusCode: resp.StatusCode,
			Errors:     envelope.Errors,
		}
	}

	if v != nil && len(envelope.Data) > 0 {
		if err := json.Unmarshal(envelope.Data, v); err != nil {
			return fmt.Errorf("failed to unmarshal response data: %w", err)
		}
	}

	return nil
}
