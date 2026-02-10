// Command signevmtx demonstrates the complete EVM transaction signing workflow
// using the Vault crypto plugin's API-driven approach.
//
// This tool uses the plugin's /tx/build/evm endpoint to construct signing data
// server-side, then calls /keys/:id/sign to produce the signature. The client
// only needs to assemble the final signed transaction for broadcasting.
//
// Workflow:
//
//	Step 1: GET  /crypto/keys/:id          -> public_key, derive ETH address
//	Step 2: POST /crypto/tx/build/evm      -> {data, prehashed, encoding}
//	Step 3: POST /crypto/keys/:id/sign     -> {signature}
//	Step 4: Assemble signed tx locally     -> raw transaction hex
//	Step 5: Broadcast via eth_sendRawTransaction (optional)
//
// Usage:
//
//	# Legacy transaction (default)
//	go run ./test/signevmtx \
//	  -key-id <uuid> -to <addr> -value 0.0001 \
//	  -nonce 1 -gas-limit 21000
//
//	# EIP-1559 transaction
//	go run ./test/signevmtx -tx-type eip1559 \
//	  -key-id <uuid> -to <addr> -value 0.0001 \
//	  -max-fee 30 -priority-fee 2 -nonce 1 -gas-limit 21000
//
// Environment variables:
//
//	VAULT_ADDR   - Vault server address (default: http://127.0.0.1:8200)
//	VAULT_TOKEN  - Vault authentication token (default: root)
//	ETH_RPC_URL  - Ethereum JSON-RPC endpoint for broadcasting (optional)
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/evmtx"
)

func main() {
	// Common flags
	keyID := flag.String("key-id", "", "Vault key internal ID (required)")
	toAddr := flag.String("to", "", "Recipient ETH address (required)")
	valueETH := flag.String("value", "0", "Value to send in ETH (e.g. 0.0001)")
	nonce := flag.Int("nonce", 0, "Transaction nonce")
	gasLimit := flag.Int("gas-limit", 21000, "Gas limit (default: 21000)")
	chainID := flag.Int("chain-id", 11155111, "Chain ID (default: 11155111 Sepolia)")
	data := flag.String("data", "", "Transaction data in hex (optional, e.g. 0xa9059cbb...)")
	broadcast := flag.Bool("broadcast", false, "Broadcast the signed transaction via ETH_RPC_URL")
	txType := flag.String("tx-type", "legacy", "Transaction type: 'legacy' or 'eip1559'")

	// Legacy-specific flags
	gasPriceWei := flag.String("gas-price", "10000000000", "Gas price in wei, legacy only (default: 10 Gwei)")

	// EIP-1559-specific flags (in Gwei for convenience)
	maxFeeGwei := flag.Float64("max-fee", 30, "Max fee per gas in Gwei, eip1559 only (default: 30)")
	priorityFeeGwei := flag.Float64("priority-fee", 2, "Max priority fee per gas in Gwei, eip1559 only (default: 2)")

	flag.Parse()

	if *keyID == "" || *toAddr == "" {
		fmt.Fprintln(os.Stderr, "Error: -key-id and -to are required")
		flag.Usage()
		os.Exit(1)
	}

	txTypeLower := strings.ToLower(*txType)
	if txTypeLower != "legacy" && txTypeLower != "eip1559" {
		fatal("Invalid -tx-type: %s (must be 'legacy' or 'eip1559')", *txType)
	}

	vaultAddr := envOrDefault("VAULT_ADDR", "http://127.0.0.1:8200")
	vaultToken := envOrDefault("VAULT_TOKEN", "root")
	ethRPCURL := os.Getenv("ETH_RPC_URL")

	// Parse value from ETH to wei string
	valueWei := parseETH(*valueETH)

	// =========================================================================
	// Step 1: Read key info to get public key and derive ETH address
	// =========================================================================
	fmt.Println("=== Step 1: Read key info ===")
	keyInfo, err := vaultGet(vaultAddr, vaultToken, fmt.Sprintf("/v1/crypto/keys/%s", *keyID))
	if err != nil {
		fatal("Failed to read key: %v", err)
	}
	publicKey := keyInfo["public_key"].(string)
	ethAddr, err := evmtx.PubKeyToChecksumAddress(publicKey)
	if err != nil {
		fatal("Failed to derive ETH address: %v", err)
	}
	fmt.Printf("  Key ID:     %s\n", *keyID)
	fmt.Printf("  Public Key: %s\n", publicKey)
	fmt.Printf("  ETH Addr:   %s\n", ethAddr)

	// =========================================================================
	// Step 2: Call /tx/build/evm API to get signing data
	// =========================================================================
	fmt.Printf("\n=== Step 2: Build signing data via API (%s) ===\n", txTypeLower)

	buildBody := map[string]interface{}{
		"tx_type":   txTypeLower,
		"chain_id":  *chainID,
		"nonce":     *nonce,
		"gas_limit": *gasLimit,
		"to":        *toAddr,
		"value":     valueWei.String(),
		"data":      *data,
	}

	switch txTypeLower {
	case "legacy":
		buildBody["gas_price"] = *gasPriceWei
		fmt.Printf("  Type:     Legacy (EIP-155)\n")
		fmt.Printf("  GasPrice: %s wei\n", *gasPriceWei)
	case "eip1559":
		maxFee := gweiToWei(*maxFeeGwei)
		priorityFee := gweiToWei(*priorityFeeGwei)
		buildBody["max_fee_per_gas"] = maxFee.String()
		buildBody["max_priority_fee_per_gas"] = priorityFee.String()
		fmt.Printf("  Type:        EIP-1559 (Dynamic Fee)\n")
		fmt.Printf("  MaxFee:      %s wei (%.2f Gwei)\n", maxFee.String(), *maxFeeGwei)
		fmt.Printf("  PriorityFee: %s wei (%.2f Gwei)\n", priorityFee.String(), *priorityFeeGwei)
	}
	fmt.Printf("  Nonce:    %d\n", *nonce)
	fmt.Printf("  GasLimit: %d\n", *gasLimit)
	fmt.Printf("  To:       %s\n", *toAddr)
	fmt.Printf("  Value:    %s wei (%s ETH)\n", valueWei.String(), *valueETH)
	fmt.Printf("  ChainID:  %d\n", *chainID)
	if *data != "" {
		fmt.Printf("  Data:     %s\n", *data)
	}

	buildResult, err := vaultPost(vaultAddr, vaultToken, "/v1/crypto/tx/build/evm", buildBody)
	if err != nil {
		fatal("Failed to build tx: %v", err)
	}
	signingData := buildResult["data"].(string)
	prehashed := buildResult["prehashed"].(bool)
	encoding := buildResult["encoding"].(string)
	fmt.Printf("  Signing Hash: %s\n", signingData)

	// =========================================================================
	// Step 3: Call /keys/:id/sign API
	// =========================================================================
	fmt.Println("\n=== Step 3: Call Vault sign API ===")
	signBody := map[string]interface{}{
		"data":          signingData,
		"prehashed":     prehashed,
		"encoding":      encoding,
		"output_format": "hex",
	}
	signResult, err := vaultPost(vaultAddr, vaultToken,
		fmt.Sprintf("/v1/crypto/keys/%s/sign", *keyID), signBody)
	if err != nil {
		fatal("Failed to sign: %v", err)
	}
	signatureHex := signResult["signature"].(string)
	fmt.Printf("  Signature: %s\n", signatureHex)

	// =========================================================================
	// Step 4: Assemble signed transaction
	// =========================================================================
	fmt.Println("\n=== Step 4: Assemble signed transaction ===")
	sigBytes, err := evmtx.ParseSignature(signatureHex)
	if err != nil {
		fatal("Failed to parse signature: %v", err)
	}
	fmt.Printf("  R: 0x%x\n", sigBytes[0:32])
	fmt.Printf("  S: 0x%x\n", sigBytes[32:64])
	fmt.Printf("  V: %d\n", sigBytes[64])

	// Reconstruct the tx struct for assembly
	signedTxBytes, err := assembleSignedTx(txTypeLower, *chainID, *nonce, *gasLimit,
		*toAddr, valueWei, *data, *gasPriceWei, *maxFeeGwei, *priorityFeeGwei, sigBytes)
	if err != nil {
		fatal("Failed to assemble signed tx: %v", err)
	}

	rawTxHex := evmtx.EncodeSignedTxForBroadcast(signedTxBytes)
	fmt.Printf("  Raw Tx:    %s\n", rawTxHex)
	fmt.Printf("  Tx Size:   %d bytes\n", len(signedTxBytes))

	// =========================================================================
	// Step 5: Broadcast (optional)
	// =========================================================================
	if *broadcast {
		if ethRPCURL == "" {
			fatal("ETH_RPC_URL is required for broadcasting")
		}
		fmt.Printf("\n=== Step 5: Broadcast to %s ===\n", ethRPCURL)

		txHash, err := ethSendRawTransaction(ethRPCURL, rawTxHex)
		if err != nil {
			fatal("Failed to broadcast: %v", err)
		}
		fmt.Printf("  Tx Hash: %s\n", txHash)
	} else {
		fmt.Println("\n=== Step 5: Broadcast (skipped) ===")
		fmt.Println("  Use -broadcast flag and set ETH_RPC_URL to broadcast")
		fmt.Println()
		fmt.Println("  Example:")
		fmt.Printf("    ETH_RPC_URL=https://rpc.sepolia.org go run ./test/signevmtx \\\n")
		fmt.Printf("      -tx-type %s -key-id %s -to %s -value %s -nonce %d -broadcast\n",
			txTypeLower, *keyID, *toAddr, *valueETH, *nonce)
	}

	fmt.Println("\n=== Done ===")
}

// assembleSignedTx reconstructs the tx struct from parameters and assembles
// the final signed transaction bytes with the given signature.
func assembleSignedTx(
	txType string, chainID, nonce, gasLimit int,
	toAddr string, value *big.Int, dataHex string,
	gasPriceWei string, maxFeeGwei, priorityFeeGwei float64,
	sig []byte,
) ([]byte, error) {
	to := parseAddress(toAddr)
	var txData []byte
	if dataHex != "" {
		txData = mustDecodeHex(dataHex)
	}

	switch txType {
	case "legacy":
		gasPrice, ok := new(big.Int).SetString(gasPriceWei, 10)
		if !ok {
			return nil, fmt.Errorf("invalid gas_price: %s", gasPriceWei)
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
		return tx.AssembleSignedTx(sig)

	case "eip1559":
		maxFee := gweiToWei(maxFeeGwei)
		priorityFee := gweiToWei(priorityFeeGwei)
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
		return tx.AssembleSignedTx(sig)

	default:
		return nil, fmt.Errorf("unsupported tx_type: %s", txType)
	}
}

// ============================================================================
// Vault API helpers
// ============================================================================

func vaultGet(addr, token, path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", addr+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	return parseVaultResponse(resp)
}

func vaultPost(addr, token, path string, body map[string]interface{}) (map[string]interface{}, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", addr+path, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	return parseVaultResponse(resp)
}

func parseVaultResponse(resp *http.Response) (map[string]interface{}, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		if errors, ok := result["errors"]; ok {
			return nil, fmt.Errorf("vault error: %v", errors)
		}
		return nil, fmt.Errorf("unexpected response format: %s", string(body))
	}
	return data, nil
}

// ============================================================================
// Ethereum JSON-RPC helper
// ============================================================================

func ethSendRawTransaction(rpcURL, rawTxHex string) (string, error) {
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendRawTransaction",
		"params":  []string{rawTxHex},
		"id":      1,
	}
	jsonBody, err := json.Marshal(rpcReq)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("RPC request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read RPC response: %w", err)
	}

	var rpcResp map[string]interface{}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return "", fmt.Errorf("failed to parse RPC response: %w", err)
	}

	if rpcErr, ok := rpcResp["error"]; ok {
		return "", fmt.Errorf("RPC error: %v", rpcErr)
	}

	txHash, ok := rpcResp["result"].(string)
	if !ok {
		return "", fmt.Errorf("unexpected RPC response: %s", string(body))
	}
	return txHash, nil
}

// ============================================================================
// Utility functions
// ============================================================================

func parseAddress(addr string) *[20]byte {
	cleaned := strings.TrimPrefix(addr, "0x")
	b := mustDecodeHex(cleaned)
	if len(b) != 20 {
		fatal("Invalid address: expected 20 bytes, got %d", len(b))
	}
	var result [20]byte
	copy(result[:], b)
	return &result
}

func parseETH(ethStr string) *big.Int {
	parts := strings.Split(ethStr, ".")
	whole := parts[0]
	frac := ""
	if len(parts) == 2 {
		frac = parts[1]
	} else if len(parts) > 2 {
		fatal("Invalid ETH value: %s", ethStr)
	}

	if len(frac) > 18 {
		fatal("ETH value too precise (max 18 decimals): %s", ethStr)
	}
	frac = frac + strings.Repeat("0", 18-len(frac))

	weiStr := whole + frac
	weiStr = strings.TrimLeft(weiStr, "0")
	if weiStr == "" {
		weiStr = "0"
	}

	wei, ok := new(big.Int).SetString(weiStr, 10)
	if !ok {
		fatal("Invalid ETH value: %s", ethStr)
	}
	return wei
}

// gweiToWei converts a Gwei float value to wei as *big.Int.
func gweiToWei(gwei float64) *big.Int {
	wholeGwei := int64(gwei)
	fracGwei := gwei - float64(wholeGwei)

	result := new(big.Int).Mul(big.NewInt(wholeGwei), big.NewInt(1_000_000_000))
	if fracGwei > 0 {
		fracWei := int64(fracGwei * 1_000_000_000)
		result.Add(result, big.NewInt(fracWei))
	}
	return result
}

func mustDecodeHex(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, err := evmtx.ParseHex(s)
	if err != nil {
		fatal("Invalid hex: %s: %v", s, err)
	}
	return b
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
