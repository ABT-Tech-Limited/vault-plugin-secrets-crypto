package backend

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/evmtx"
)

func pathTxBuild(b *CryptoBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "tx/build/evm",
			Fields: map[string]*framework.FieldSchema{
				"tx_type": {
					Type:        framework.TypeString,
					Description: "Transaction type: 'legacy' or 'eip1559'",
					Required:    true,
				},
				"chain_id": {
					Type:        framework.TypeInt,
					Description: "Chain ID (e.g. 1=Mainnet, 11155111=Sepolia)",
					Required:    true,
				},
				"nonce": {
					Type:        framework.TypeInt,
					Description: "Transaction nonce",
					Required:    true,
				},
				"gas_limit": {
					Type:        framework.TypeInt,
					Description: "Gas limit",
					Required:    true,
				},
				"to": {
					Type:        framework.TypeString,
					Description: "Recipient address in hex with 0x prefix (empty for contract creation)",
				},
				"value": {
					Type:        framework.TypeString,
					Description: "Transfer value in wei (decimal string, default '0')",
					Default:     "0",
				},
				"data": {
					Type:        framework.TypeString,
					Description: "Transaction data in hex (optional, e.g. 0xa9059cbb...)",
				},
				// Legacy fields
				"gas_price": {
					Type:        framework.TypeString,
					Description: "Gas price in wei (decimal string, legacy tx only)",
				},
				// EIP-1559 fields
				"max_fee_per_gas": {
					Type:        framework.TypeString,
					Description: "Max fee per gas in wei (decimal string, eip1559 tx only)",
				},
				"max_priority_fee_per_gas": {
					Type:        framework.TypeString,
					Description: "Max priority fee per gas in wei (decimal string, eip1559 tx only)",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathTxBuildEVM,
					Summary:  "Build EVM transaction signing data",
				},
			},
			HelpSynopsis:    "Build EVM transaction signing data for use with the sign API",
			HelpDescription: pathTxBuildHelpDescription,
		},
	}
}

// pathTxBuildEVM handles POST /tx/build/evm
func (b *CryptoBackend) pathTxBuildEVM(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	// Parse common parameters
	txType := strings.ToLower(d.Get("tx_type").(string))
	chainID := d.Get("chain_id").(int)
	nonce := d.Get("nonce").(int)
	gasLimit := d.Get("gas_limit").(int)
	toStr := d.Get("to").(string)
	valueStr := d.Get("value").(string)
	dataStr := d.Get("data").(string)

	// Validate tx_type
	if txType != "legacy" && txType != "eip1559" {
		return logical.ErrorResponse("tx_type must be 'legacy' or 'eip1559'"), nil
	}

	// Validate numeric fields
	if chainID <= 0 {
		return logical.ErrorResponse("chain_id must be positive"), nil
	}
	if nonce < 0 {
		return logical.ErrorResponse("nonce must be non-negative"), nil
	}
	if gasLimit <= 0 {
		return logical.ErrorResponse("gas_limit must be positive"), nil
	}

	// Parse 'to' address
	var to *[20]byte
	if toStr != "" {
		addr, err := parseEthAddress(toStr)
		if err != nil {
			return logical.ErrorResponse("invalid 'to' address: %s", err.Error()), nil
		}
		to = addr
	}

	// Parse 'value'
	value, ok := new(big.Int).SetString(valueStr, 10)
	if !ok {
		return logical.ErrorResponse("invalid 'value': must be a decimal string"), nil
	}
	if value.Sign() < 0 {
		return logical.ErrorResponse("value must be non-negative"), nil
	}

	// Parse 'data'
	var txData []byte
	if dataStr != "" {
		cleaned := strings.TrimPrefix(dataStr, "0x")
		var err error
		txData, err = hex.DecodeString(cleaned)
		if err != nil {
			return logical.ErrorResponse("invalid 'data': %s", err.Error()), nil
		}
	}

	// Build transaction and compute signing hash
	var signingHash []byte

	switch txType {
	case "legacy":
		gasPriceStr := d.Get("gas_price").(string)
		if gasPriceStr == "" {
			return logical.ErrorResponse("gas_price is required for legacy transactions"), nil
		}
		gasPrice, ok := new(big.Int).SetString(gasPriceStr, 10)
		if !ok {
			return logical.ErrorResponse("invalid 'gas_price': must be a decimal string"), nil
		}
		if gasPrice.Sign() < 0 {
			return logical.ErrorResponse("gas_price must be non-negative"), nil
		}

		tx := &evmtx.LegacyTx{
			Nonce:    uint64(nonce),
			GasPrice: gasPrice,
			GasLimit: uint64(gasLimit),
			To:       to,
			Value:    value,
			Data:     txData,
			ChainID:  big.NewInt(int64(chainID)),
		}
		signingHash = tx.SigningHash()

	case "eip1559":
		maxFeeStr := d.Get("max_fee_per_gas").(string)
		priorityFeeStr := d.Get("max_priority_fee_per_gas").(string)
		if maxFeeStr == "" {
			return logical.ErrorResponse("max_fee_per_gas is required for eip1559 transactions"), nil
		}
		if priorityFeeStr == "" {
			return logical.ErrorResponse("max_priority_fee_per_gas is required for eip1559 transactions"), nil
		}

		maxFee, ok := new(big.Int).SetString(maxFeeStr, 10)
		if !ok {
			return logical.ErrorResponse("invalid 'max_fee_per_gas': must be a decimal string"), nil
		}
		priorityFee, ok := new(big.Int).SetString(priorityFeeStr, 10)
		if !ok {
			return logical.ErrorResponse("invalid 'max_priority_fee_per_gas': must be a decimal string"), nil
		}
		if maxFee.Sign() < 0 {
			return logical.ErrorResponse("max_fee_per_gas must be non-negative"), nil
		}
		if priorityFee.Sign() < 0 {
			return logical.ErrorResponse("max_priority_fee_per_gas must be non-negative"), nil
		}

		tx := &evmtx.DynamicFeeTx{
			ChainID:              big.NewInt(int64(chainID)),
			Nonce:                uint64(nonce),
			MaxPriorityFeePerGas: priorityFee,
			MaxFeePerGas:         maxFee,
			GasLimit:             uint64(gasLimit),
			To:                   to,
			Value:                value,
			Data:                 txData,
			AccessList:           nil,
		}
		signingHash = tx.SigningHash()
	}

	signReq := evmtx.PrepareSignRequest(signingHash)

	return &logical.Response{
		Data: map[string]interface{}{
			"data":         signReq.Data,
			"prehashed":    signReq.Prehashed,
			"encoding":     signReq.Encoding,
			"tx_type":      txType,
			"signing_hash": signReq.Data,
		},
	}, nil
}

// parseEthAddress parses a hex Ethereum address string into a [20]byte.
func parseEthAddress(addr string) (*[20]byte, error) {
	cleaned := strings.TrimPrefix(addr, "0x")
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, err
	}
	if len(b) != 20 {
		return nil, fmt.Errorf("expected 20 bytes, got %d", len(b))
	}
	var result [20]byte
	copy(result[:], b)
	return &result, nil
}

const pathTxBuildHelpDescription = `
This endpoint builds EVM transaction signing data that can be directly
passed to the /keys/:id/sign endpoint.

Supported transaction types:
  - legacy: EIP-155 transactions (requires gas_price)
  - eip1559: EIP-1559 dynamic fee transactions (requires max_fee_per_gas, max_priority_fee_per_gas)

Workflow:
  1. POST /tx/build/evm with transaction parameters
     -> Returns {data, prehashed, encoding}
  2. POST /keys/:id/sign with the output from step 1
     -> Returns {signature}

Example (Legacy):
  curl -X POST -H "X-Vault-Token: $TOKEN" \
    -d '{"tx_type":"legacy","chain_id":11155111,"nonce":0,"gas_limit":21000,"to":"0x...","value":"100000000000000","gas_price":"10000000000"}' \
    $VAULT_ADDR/v1/crypto/tx/build/evm

Example (EIP-1559):
  curl -X POST -H "X-Vault-Token: $TOKEN" \
    -d '{"tx_type":"eip1559","chain_id":1,"nonce":0,"gas_limit":21000,"to":"0x...","value":"1000000000000000000","max_fee_per_gas":"30000000000","max_priority_fee_per_gas":"2000000000"}' \
    $VAULT_ADDR/v1/crypto/tx/build/evm
`
