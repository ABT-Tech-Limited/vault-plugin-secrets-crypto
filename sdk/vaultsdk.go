package vaultsdk

import "context"

// Client defines the interface for interacting with the Vault crypto plugin.
type Client interface {
	// CreateKey creates a new cryptographic key pair.
	CreateKey(ctx context.Context, req *CreateKeyRequest) (*Key, error)

	// ListKeys returns a list of all key external IDs.
	ListKeys(ctx context.Context) ([]string, error)

	// ReadKey retrieves key information by its external ID.
	ReadKey(ctx context.Context, externalID string) (*Key, error)

	// Sign signs data with the specified key.
	Sign(ctx context.Context, externalID string, req *SignRequest) (*SignResponse, error)

	// BuildEVMTransaction builds EVM transaction signing data.
	BuildEVMTransaction(ctx context.Context, req *BuildEVMTransactionRequest) (*BuildEVMTransactionResponse, error)
}

// Key represents the public information about a cryptographic key.
type Key struct {
	// Name is the user-provided name.
	Name string `json:"name"`

	// ExternalID is the user-provided external identifier.
	ExternalID string `json:"external_id"`

	// Curve is the elliptic curve type: "secp256k1", "secp256r1", or "ed25519".
	Curve string `json:"curve"`

	// PublicKey is the hex-encoded public key (with "0x" prefix).
	PublicKey string `json:"public_key"`

	// CreatedAt is the key creation timestamp in RFC3339 format.
	CreatedAt string `json:"created_at"`

	// Metadata is optional user-defined key-value metadata.
	Metadata map[string]string `json:"metadata"`
}

// CreateKeyRequest contains the parameters for creating a new key.
type CreateKeyRequest struct {
	// Curve is the elliptic curve type (required).
	// Valid values: "secp256k1", "secp256r1", "ed25519".
	Curve string `json:"curve"`

	// Name is a unique name for the key (required).
	Name string `json:"name"`

	// ExternalID is a unique external identifier (required).
	ExternalID string `json:"external_id"`

	// Metadata is optional key-value metadata (max 16 keys).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SignRequest contains the parameters for signing data.
type SignRequest struct {
	// Data is the data to sign (hex or base64 encoded, required).
	Data string `json:"data"`

	// Encoding is the input encoding: "hex" (default) or "base64".
	Encoding string `json:"encoding,omitempty"`

	// OutputFormat is the output format: "hex" (default), "base64", or "raw".
	OutputFormat string `json:"output_format,omitempty"`

	// Prehashed indicates whether the data is already hashed.
	// Default is true on the server side. Use a pointer to distinguish
	// between "not set" (nil, uses server default) and "explicitly false".
	Prehashed *bool `json:"prehashed,omitempty"`
}

// SignResponse contains the signing result.
type SignResponse struct {
	// Signature is the signature output in the requested format.
	Signature string `json:"signature"`

	// Curve is the elliptic curve type used for signing.
	Curve string `json:"curve"`

	// ExternalID is the key's external identifier.
	ExternalID string `json:"external_id"`
}

// BuildEVMTransactionRequest contains the parameters for building
// EVM transaction signing data.
type BuildEVMTransactionRequest struct {
	// TxType is the transaction type (required): "legacy" or "eip1559".
	TxType string `json:"tx_type"`

	// ChainID is the chain identifier (required, e.g., 1 for Mainnet).
	ChainID int `json:"chain_id"`

	// Nonce is the transaction nonce (required, >= 0).
	Nonce int `json:"nonce"`

	// GasLimit is the gas limit (required, > 0).
	GasLimit int `json:"gas_limit"`

	// To is the recipient address in hex with "0x" prefix.
	// Leave empty for contract creation.
	To string `json:"to,omitempty"`

	// Value is the transfer value in wei as a decimal string (default: "0").
	Value string `json:"value,omitempty"`

	// Data is the transaction calldata in hex (optional).
	Data string `json:"data,omitempty"`

	// GasPrice is the gas price in wei as a decimal string.
	// Required for legacy transactions.
	GasPrice string `json:"gas_price,omitempty"`

	// MaxFeePerGas is the max fee per gas in wei as a decimal string.
	// Required for eip1559 transactions.
	MaxFeePerGas string `json:"max_fee_per_gas,omitempty"`

	// MaxPriorityFeePerGas is the max priority fee per gas in wei as a decimal string.
	// Required for eip1559 transactions.
	MaxPriorityFeePerGas string `json:"max_priority_fee_per_gas,omitempty"`
}

// BuildEVMTransactionResponse contains the result of building an EVM transaction.
type BuildEVMTransactionResponse struct {
	// Data is the hex-encoded signing hash (with "0x" prefix).
	// This value can be passed directly to the Sign endpoint.
	Data string `json:"data"`

	// Prehashed indicates the data is already hashed (always true for EVM tx).
	Prehashed bool `json:"prehashed"`

	// Encoding is the data encoding format (always "hex").
	Encoding string `json:"encoding"`

	// TxType is the transaction type that was built.
	TxType string `json:"tx_type"`

	// SigningHash is the hex-encoded Keccak256 signing hash (same as Data).
	SigningHash string `json:"signing_hash"`
}
