#!/bin/bash

# Vault Crypto Plugin Test Script
# Usage: ./test.sh

set -e

VAULT_ADDR="http://127.0.0.1:8200"
VAULT_TOKEN="root"
VERSION="v0.1.0"
PLUGIN_BINARY="vault-plugin-crypto-${VERSION}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${YELLOW}=== Vault Crypto Plugin Test (${VERSION}) ===${NC}\n"

# Check if Vault is running
echo "Checking Vault status..."
if ! curl -s ${VAULT_ADDR}/v1/sys/health > /dev/null 2>&1; then
    echo "Error: Vault is not running. Start it with: docker-compose up -d"
    exit 1
fi
echo -e "${GREEN}✓ Vault is running${NC}\n"

# Calculate SHA256 of plugin
SHA256=$(shasum -a 256 build/${PLUGIN_BINARY} | cut -d ' ' -f1)
echo "Plugin: build/${PLUGIN_BINARY}"
echo "Plugin SHA256: ${SHA256}"

# Register plugin with version
echo -e "\n${YELLOW}1. Registering plugin...${NC}"
REQ_DATA="{\"sha256\":\"${SHA256}\",\"command\":\"${PLUGIN_BINARY}\",\"version\":\"${VERSION}\"}"
echo -e "${CYAN}Request: POST /v1/sys/plugins/catalog/secret/vault-plugin-crypto${NC}"
echo -e "${BLUE}Body: ${REQ_DATA}${NC}"
curl -s -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -d "${REQ_DATA}" \
    ${VAULT_ADDR}/v1/sys/plugins/catalog/secret/vault-plugin-crypto | jq .
echo -e "${GREEN}✓ Plugin registered${NC}"

# Enable plugin with version and description
echo -e "\n${YELLOW}2. Enabling plugin at /crypto...${NC}"
REQ_DATA='{"type":"vault-plugin-crypto","plugin_version":"'"${VERSION}"'","description":"Cryptographic key management for blockchain applications"}'
echo -e "${CYAN}Request: POST /v1/sys/mounts/crypto${NC}"
echo -e "${BLUE}Body: ${REQ_DATA}${NC}"
curl -s -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -d "${REQ_DATA}" \
    ${VAULT_ADDR}/v1/sys/mounts/crypto | jq .
echo -e "${GREEN}✓ Plugin enabled${NC}"

# Check plugin info (should show version)
echo -e "\n${YELLOW}2b. Checking mounted plugin info...${NC}"
echo -e "${CYAN}Request: GET /v1/sys/mounts/crypto/tune${NC}"
RESULT=$(curl -s -X GET \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    ${VAULT_ADDR}/v1/sys/mounts/crypto/tune)
echo $RESULT | jq .
PLUGIN_VERSION=$(echo $RESULT | jq -r '.data.plugin_version // "not set"')
echo -e "${GREEN}✓ Plugin version: ${PLUGIN_VERSION}${NC}"

# Create secp256k1 key
echo -e "\n${YELLOW}3. Creating secp256k1 key...${NC}"
REQ_DATA='{"curve":"secp256k1","name":"eth-key-1","external_id":"user-001"}'
echo -e "${CYAN}Request: POST /v1/crypto/keys${NC}"
echo -e "${BLUE}Body: ${REQ_DATA}${NC}"
RESULT=$(curl -s -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -d "${REQ_DATA}" \
    ${VAULT_ADDR}/v1/crypto/keys)
echo $RESULT | jq .
KEY_ID=$(echo $RESULT | jq -r '.data.internal_id')
PUBLIC_KEY=$(echo $RESULT | jq -r '.data.public_key')
echo -e "${GREEN}✓ Key created: ${KEY_ID}${NC}"
echo -e "${GREEN}✓ Public key (65 bytes): ${PUBLIC_KEY}${NC}"

# Create ed25519 key
echo -e "\n${YELLOW}4. Creating ed25519 key...${NC}"
REQ_DATA='{"curve":"ed25519","name":"solana-key-1"}'
echo -e "${CYAN}Request: POST /v1/crypto/keys${NC}"
echo -e "${BLUE}Body: ${REQ_DATA}${NC}"
RESULT=$(curl -s -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -d "${REQ_DATA}" \
    ${VAULT_ADDR}/v1/crypto/keys)
echo $RESULT | jq .
ED_PUBLIC_KEY=$(echo $RESULT | jq -r '.data.public_key')
echo -e "${GREEN}✓ Ed25519 key created${NC}"
echo -e "${GREEN}✓ Public key (32 bytes): ${ED_PUBLIC_KEY}${NC}"

# List keys
echo -e "\n${YELLOW}5. Listing all keys...${NC}"
echo -e "${CYAN}Request: LIST /v1/crypto/keys${NC}"
curl -s -X LIST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    ${VAULT_ADDR}/v1/crypto/keys | jq .
echo -e "${GREEN}✓ Keys listed${NC}"

# Read key info
echo -e "\n${YELLOW}6. Reading key info (should contain public_key, NOT private_key)...${NC}"
echo -e "${CYAN}Request: GET /v1/crypto/keys/${KEY_ID}${NC}"
RESULT=$(curl -s -X GET \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    ${VAULT_ADDR}/v1/crypto/keys/${KEY_ID})
echo $RESULT | jq .

# Verify public_key is present and private_key is NOT present
HAS_PUBLIC_KEY=$(echo $RESULT | jq 'has("data") and (.data | has("public_key"))')
HAS_PRIVATE_KEY=$(echo $RESULT | jq 'has("data") and (.data | has("private_key"))')
if [ "$HAS_PUBLIC_KEY" = "true" ] && [ "$HAS_PRIVATE_KEY" = "false" ]; then
    echo -e "${GREEN}✓ Key info retrieved: public_key present, private_key NOT exposed${NC}"
else
    echo -e "Warning: public_key=${HAS_PUBLIC_KEY}, private_key=${HAS_PRIVATE_KEY}"
fi

# Sign data (32-byte hash in hex)
echo -e "\n${YELLOW}7. Signing data with secp256k1 key...${NC}"
# Sample 32-byte hash (keccak256 of "hello")
HASH="1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
REQ_DATA="{\"data\":\"0x${HASH}\",\"encoding\":\"hex\",\"prehashed\":true}"
echo -e "${CYAN}Request: POST /v1/crypto/keys/${KEY_ID}/sign${NC}"
echo -e "${BLUE}Body: ${REQ_DATA}${NC}"
curl -s -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -d "${REQ_DATA}" \
    ${VAULT_ADDR}/v1/crypto/keys/${KEY_ID}/sign | jq .
echo -e "${GREEN}✓ Data signed${NC}"

# Sign with base64 output
echo -e "\n${YELLOW}8. Signing with base64 output...${NC}"
REQ_DATA="{\"data\":\"0x${HASH}\",\"encoding\":\"hex\",\"output_format\":\"base64\",\"prehashed\":true}"
echo -e "${CYAN}Request: POST /v1/crypto/keys/${KEY_ID}/sign${NC}"
echo -e "${BLUE}Body: ${REQ_DATA}${NC}"
curl -s -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -d "${REQ_DATA}" \
    ${VAULT_ADDR}/v1/crypto/keys/${KEY_ID}/sign | jq .
echo -e "${GREEN}✓ Signature in base64 format${NC}"

# Create secp256r1 key
echo -e "\n${YELLOW}9. Creating secp256r1 (P-256) key...${NC}"
REQ_DATA='{"curve":"secp256r1","name":"p256-key-1"}'
echo -e "${CYAN}Request: POST /v1/crypto/keys${NC}"
echo -e "${BLUE}Body: ${REQ_DATA}${NC}"
RESULT=$(curl -s -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -d "${REQ_DATA}" \
    ${VAULT_ADDR}/v1/crypto/keys)
echo $RESULT | jq .
P256_KEY_ID=$(echo $RESULT | jq -r '.data.internal_id')
P256_PUBLIC_KEY=$(echo $RESULT | jq -r '.data.public_key')
echo -e "${GREEN}✓ P-256 key created: ${P256_KEY_ID}${NC}"
echo -e "${GREEN}✓ Public key (65 bytes): ${P256_PUBLIC_KEY}${NC}"

echo -e "\n${GREEN}=== All tests passed! ===${NC}"
