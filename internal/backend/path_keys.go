package backend

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/crypto"
	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/model"
	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/storage"
)

func pathKeys(b *CryptoBackend) []*framework.Path {
	return []*framework.Path{
		{
			// POST /keys - Create a new key
			// LIST /keys - List all keys
			Pattern: "keys/?$",
			Fields: map[string]*framework.FieldSchema{
				"curve": {
					Type:        framework.TypeString,
					Description: "Elliptic curve type: secp256k1, secp256r1, or ed25519",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Name for the key (required, alphanumeric, underscore, hyphen only)",
					Required:    true,
				},
				"external_id": {
					Type:        framework.TypeString,
					Description: "Unique external identifier for the key (required, alphanumeric, dot, underscore, hyphen only)",
					Required:    true,
				},
				"metadata": {
					Type:        framework.TypeKVPairs,
					Description: "Optional key-value metadata (max 16 keys)",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeyCreate,
					Summary:  "Create a new cryptographic key pair",
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathKeyList,
					Summary:  "List all keys",
				},
			},
			HelpSynopsis:    "Create or list cryptographic keys",
			HelpDescription: pathKeysHelpDescription,
		},
		{
			// GET /keys/:external_id - Read key info
			Pattern: "keys/" + framework.GenericNameRegex("external_id"),
			Fields: map[string]*framework.FieldSchema{
				"external_id": {
					Type:        framework.TypeString,
					Description: "External identifier of the key",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathKeyRead,
					Summary:  "Read key information (without private key)",
				},
			},
			HelpSynopsis:    "Read a specific key",
			HelpDescription: "Read key information (never includes private key) by its external ID.",
		},
	}
}

// pathKeyCreate handles POST /keys
func (b *CryptoBackend) pathKeyCreate(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	// Parse parameters
	curveStr := d.Get("curve").(string)
	name := d.Get("name").(string)
	externalID := d.Get("external_id").(string)
	metadataRaw := d.Get("metadata")
	var metadata map[string]string
	if metadataRaw != nil {
		metadata = metadataRaw.(map[string]string)
	}

	// Validate curve
	curve := model.CurveType(curveStr)
	if !curve.IsValid() {
		return logical.ErrorResponse("invalid curve type: must be secp256k1, secp256r1, or ed25519"), nil
	}

	// Validate name
	if err := ValidateName(name); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Validate external_id
	if err := ValidateExternalID(externalID); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Validate metadata
	if err := ValidateMetadata(metadata); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Create signer and generate key
	signer, err := crypto.NewSigner(curve)
	if err != nil {
		return nil, err
	}

	privateKey, err := signer.GenerateKey()
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(privateKey)

	// Create key record
	key := &model.Key{
		InternalID: uuid.New().String(),
		Name:       name,
		ExternalID: externalID,
		Curve:      curve,
		PrivateKey: privateKey,
		CreatedAt:  time.Now().UTC(),
		Metadata:   metadata,
	}

	// Store key
	ks := storage.NewKeyStorage(req.Storage)
	if err := ks.SaveKey(ctx, key); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Get public key
	pubKeyBytes, err := signer.PublicKey()
	if err != nil {
		return nil, err
	}

	// Return key info with public key
	keyInfo := key.ToInfo()
	keyInfo.PublicKey = "0x" + hex.EncodeToString(pubKeyBytes)

	return &logical.Response{
		Data: keyInfo.ToResponseData(),
	}, nil
}

// pathKeyRead handles GET /keys/:external_id
func (b *CryptoBackend) pathKeyRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	externalID := d.Get("external_id").(string)
	if externalID == "" {
		return logical.ErrorResponse("external_id is required"), nil
	}

	ks := storage.NewKeyStorage(req.Storage)
	key, err := ks.GetByExternalID(ctx, externalID)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return logical.ErrorResponse("key not found"), nil
	}

	// Calculate public key from private key
	signer, err := crypto.NewSignerWithKey(key.Curve, key.PrivateKey)
	if err != nil {
		return nil, err
	}
	pubKeyBytes, err := signer.PublicKey()
	if err != nil {
		return nil, err
	}

	// Return key info with public key
	keyInfo := key.ToInfo()
	keyInfo.PublicKey = "0x" + hex.EncodeToString(pubKeyBytes)

	return &logical.Response{
		Data: keyInfo.ToResponseData(),
	}, nil
}

// pathKeyList handles LIST /keys
func (b *CryptoBackend) pathKeyList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	ks := storage.NewKeyStorage(req.Storage)
	ids, err := ks.ListExternalIDs(ctx)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(ids), nil
}

const pathKeysHelpDescription = `
This endpoint manages cryptographic keys for blockchain applications.

CREATE (POST /keys):
  Required:
    - curve: The elliptic curve type (secp256k1, secp256r1, or ed25519)
    - name: A name for the key (alphanumeric, underscore, hyphen)
    - external_id: A unique external identifier (alphanumeric, dot, underscore, hyphen)

  Optional:
    - metadata: Key-value pairs for additional information

  Returns:
    - name, external_id, curve, public_key, created_at, metadata

LIST (GET /keys):
  Returns a list of all key external IDs.

READ (GET /keys/:external_id):
  Returns key information by external_id (excluding private keys).

Security:
  - Private keys are never returned in any response
  - Keys are encrypted at rest using Vault's storage encryption
  - SealWrap provides additional encryption for key material
`
