package backend

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/crypto"
	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/storage"
)

func pathKeysSign(b *CryptoBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "keys/" + framework.GenericNameRegex("external_id") + "/sign",
			Fields: map[string]*framework.FieldSchema{
				"external_id": {
					Type:        framework.TypeString,
					Description: "External identifier of the key",
					Required:    true,
				},
				"data": {
					Type:        framework.TypeString,
					Description: "Data to sign (hex or base64 encoded)",
					Required:    true,
				},
				"encoding": {
					Type:        framework.TypeString,
					Description: "Input encoding: 'hex' or 'base64' (default: hex)",
					Default:     "hex",
				},
				"output_format": {
					Type:        framework.TypeString,
					Description: "Output format: 'hex', 'base64', or 'raw' (default: hex)",
					Default:     "hex",
				},
				"prehashed": {
					Type:        framework.TypeBool,
					Description: "If true, data is already hashed (default: true for ECDSA curves)",
					Default:     true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeySign,
					Summary:  "Sign data with the specified key",
				},
			},
			HelpSynopsis:    "Sign data using a cryptographic key",
			HelpDescription: pathKeysSignHelpDescription,
		},
	}
}

// pathKeySign handles POST /keys/:external_id/sign
func (b *CryptoBackend) pathKeySign(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	// Parse parameters
	externalID := d.Get("external_id").(string)
	dataStr := d.Get("data").(string)
	encoding := d.Get("encoding").(string)
	outputFormat := d.Get("output_format").(string)
	prehashed := d.Get("prehashed").(bool)

	// Validate parameters
	if externalID == "" {
		return logical.ErrorResponse("external_id is required"), nil
	}
	if dataStr == "" {
		return logical.ErrorResponse("data is required"), nil
	}

	// Get key from storage
	ks := storage.NewKeyStorage(req.Storage)
	key, err := ks.GetByExternalID(ctx, externalID)
	if err != nil {
		// Don't expose internal errors
		return logical.ErrorResponse("failed to retrieve key"), nil
	}
	if key == nil {
		return logical.ErrorResponse("key not found"), nil
	}

	// Decode input data
	var data []byte
	switch strings.ToLower(encoding) {
	case "hex":
		// Remove optional 0x prefix
		dataStr = strings.TrimPrefix(dataStr, "0x")
		data, err = hex.DecodeString(dataStr)
		if err != nil {
			return logical.ErrorResponse("invalid hex encoding"), nil
		}
	case "base64":
		data, err = base64.StdEncoding.DecodeString(dataStr)
		if err != nil {
			return logical.ErrorResponse("invalid base64 encoding"), nil
		}
	default:
		return logical.ErrorResponse("encoding must be 'hex' or 'base64'"), nil
	}

	// Validate data
	if err := ValidateSignData(data); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Create signer with the private key
	signer, err := crypto.NewSignerWithKey(key.Curve, key.PrivateKey)
	if err != nil {
		return logical.ErrorResponse("failed to create signer"), nil
	}

	// Zero the private key copy after use
	defer crypto.ZeroBytes(key.PrivateKey)

	// Sign the data
	signature, err := signer.Sign(data, prehashed)
	if err != nil {
		return logical.ErrorResponse("signing failed: " + err.Error()), nil
	}

	// Format output
	var signatureStr string
	switch strings.ToLower(outputFormat) {
	case "hex":
		signatureStr = "0x" + hex.EncodeToString(signature)
	case "base64":
		signatureStr = base64.StdEncoding.EncodeToString(signature)
	case "raw":
		signatureStr = hex.EncodeToString(signature)
	default:
		return logical.ErrorResponse("output_format must be 'hex', 'base64', or 'raw'"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature":   signatureStr,
			"curve":       string(key.Curve),
			"external_id": key.ExternalID,
		},
	}, nil
}

const pathKeysSignHelpDescription = `
This endpoint signs data using the specified cryptographic key.

Request:
  - external_id (path): The external identifier of the key to use for signing
  - data (required): The data to sign (hex or base64 encoded)
  - encoding: Input encoding - 'hex' (default) or 'base64'
  - output_format: Output format - 'hex' (default), 'base64', or 'raw'
  - prehashed: If true, data is already hashed (default: true)

Response:
  - signature: The signature in the requested format
  - curve: The curve type used for signing
  - external_id: The key's external identifier

Signature Formats by Curve:
  - secp256k1: 65 bytes (R[32] || S[32] || V[1]) - Ethereum compatible
  - secp256r1: 64 bytes (R[32] || S[32]) - Standard ECDSA
  - ed25519: 64 bytes - Standard Ed25519

Input Requirements:
  - For secp256k1/secp256r1 with prehashed=true: 32 bytes (hash)
  - For ed25519: Any length (internal hashing)

Examples:
  # Sign a Keccak256 hash for Ethereum
  curl -X POST -H "X-Vault-Token: $TOKEN" \
    -d '{"data":"0x1234...","encoding":"hex","prehashed":true}' \
    $VAULT_ADDR/v1/crypto/keys/<external_id>/sign

  # Sign raw message with Ed25519
  curl -X POST -H "X-Vault-Token: $TOKEN" \
    -d '{"data":"SGVsbG8gV29ybGQ=","encoding":"base64","prehashed":false}' \
    $VAULT_ADDR/v1/crypto/keys/<external_id>/sign
`
