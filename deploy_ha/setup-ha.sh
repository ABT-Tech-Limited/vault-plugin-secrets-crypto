#!/usr/bin/env bash
# Vault Crypto Plugin - HA Cluster Deployment Helper Script
#
# Usage: ./setup-ha.sh <command>
#
# Commands:
#   init-dirs       Create required directory structure
#   gen-ca          Generate CA certificate (run once, distribute to all nodes)
#   gen-cert        Generate node TLS certificate using shared CA
#   prepare-config  Generate vault.hcl from .env settings
#   start           Start Vault container on this node
#   stop            Stop Vault container on this node
#   vault-init      Initialize Vault cluster (run on node-1 only)
#   vault-unseal    Unseal Vault on this node (Shamir mode)
#   register-plugin Register and enable the crypto plugin (run on leader only)
#   status          Show this node's Vault status
#   raft-status     Show Raft cluster member list
#   gen-backup-token Create a least-privilege backup token (run on leader)
#   token-status    Show a token's TTL, policies and renewal health
#   backup          Create a Raft snapshot backup (online, no downtime)
#   restore         Restore a snapshot into this cluster (seal check enforced)
#   restore-force   Restore a snapshot into a fresh cluster (disaster recovery)
#   list-keys       List crypto plugin keys
#   key-info        Show one crypto key by external_id
#   help            Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Load .env file
load_env() {
  if [ ! -f .env ]; then
    error ".env file not found. Run: cp .env.example .env && vim .env"
    exit 1
  fi
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
}

# Determine Vault address scheme
vault_scheme() {
  if [ "${TLS_DISABLE:-false}" = "true" ]; then
    echo "http"
  else
    echo "https"
  fi
}

vault_addr() {
  echo "$(vault_scheme)://127.0.0.1:${VAULT_PORT:-8200}"
}

curl_vault() {
  local extra_args=()
  if [ "${TLS_DISABLE:-false}" != "true" ] && [ -f tls/ca.pem ]; then
    extra_args+=(--cacert tls/ca.pem)
  elif [ "${TLS_DISABLE:-false}" != "true" ]; then
    extra_args+=(-k)
  fi
  curl -s "${extra_args[@]}" "$@"
}

# ==================== Commands ====================

cmd_init_dirs() {
  info "Creating directory structure..."
  mkdir -p config tls logs backups plugins
  chmod 700 config tls

  # Check plugin binary
  local plugin_binary="${PLUGIN_NAME:-vault-plugin-crypto}-${PLUGIN_VERSION:-v0.2.0}"
  if [ -f "plugins/${plugin_binary}" ]; then
    ok "Plugin binary found: plugins/${plugin_binary}"
  else
    warn "Plugin binary not found: plugins/${plugin_binary}"
    warn "Copy the linux/amd64 plugin binary to plugins/ directory."
  fi

  ok "Directories created: config/ tls/ logs/ backups/ plugins/"
}

cmd_gen_ca() {
  info "Generating CA certificate..."
  warn "Run this on ONE machine only, then distribute ca.pem and ca-key.pem to all nodes."

  mkdir -p tls

  if [ -f tls/ca.pem ] && [ -f tls/ca-key.pem ]; then
    warn "CA files already exist in tls/. Skipping."
    warn "To regenerate, remove tls/ca.pem and tls/ca-key.pem first."
    return
  fi

  openssl genrsa -out tls/ca-key.pem 4096 2>/dev/null
  openssl req -new -x509 -days 3650 -key tls/ca-key.pem \
    -out tls/ca.pem -subj "/CN=Vault HA Cluster CA" 2>/dev/null
  chmod 600 tls/ca-key.pem tls/ca.pem

  ok "CA certificate generated (valid 10 years):"
  info "  CA cert: tls/ca.pem"
  info "  CA key:  tls/ca-key.pem"
  echo ""
  echo -e "${YELLOW}===========================================================${NC}"
  echo -e "${YELLOW}  Next steps:${NC}"
  echo -e "${YELLOW}  1. Copy tls/ca.pem and tls/ca-key.pem to ALL 3 nodes${NC}"
  echo -e "${YELLOW}  2. Run './setup-ha.sh gen-cert' on EACH node${NC}"
  echo -e "${YELLOW}===========================================================${NC}"
}

cmd_gen_cert() {
  info "Generating node TLS certificate..."

  local fqdn="${VAULT_FQDN:-localhost}"

  if [ ! -f tls/ca.pem ] || [ ! -f tls/ca-key.pem ]; then
    error "CA files not found. Either:"
    error "  1. Run './setup-ha.sh gen-ca' on one machine first, or"
    error "  2. Copy ca.pem and ca-key.pem from the CA machine to tls/"
    exit 1
  fi

  if [ -f tls/cert.pem ] && [ -f tls/key.pem ]; then
    warn "Node certificate already exists. Skipping."
    warn "To regenerate, remove tls/cert.pem and tls/key.pem first."
    return
  fi

  # Collect all node FQDNs/IPs for SAN.
  # VAULT_SAN_IP adds the node's private IP as an IP SAN entry — required when
  # peers/clients connect by IP, since TLS verifies IPs against iPAddress SANs
  # (a DNS:<ip> entry does NOT satisfy IP verification).
  local san="DNS:${fqdn},DNS:localhost,IP:127.0.0.1"
  if [ -n "${VAULT_SAN_IP:-}" ]; then
    san="${san},IP:${VAULT_SAN_IP}"
  fi

  # Create SAN config
  cat > tls/_openssl.cnf <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
[req_dn]
[v3_req]
subjectAltName = ${san}
EOF

  # Generate node key, CSR, and certificate
  openssl genrsa -out tls/key.pem 4096 2>/dev/null
  openssl req -new -key tls/key.pem -out tls/_vault.csr \
    -subj "/CN=${fqdn}" 2>/dev/null
  openssl x509 -req -days 365 -in tls/_vault.csr \
    -CA tls/ca.pem -CAkey tls/ca-key.pem -CAcreateserial \
    -out tls/cert.pem -extfile tls/_openssl.cnf -extensions v3_req 2>/dev/null

  # Cleanup temp files
  rm -f tls/_vault.csr tls/_openssl.cnf tls/ca.srl
  chmod 600 tls/key.pem tls/cert.pem

  ok "Node certificate generated:"
  info "  Cert: tls/cert.pem (SAN: ${san})"
  info "  Key:  tls/key.pem"
}

cmd_prepare_config() {
  info "Generating Vault HA configuration..."

  local unseal="${UNSEAL_METHOD:-shamir}"
  local template="vault-${unseal}-ha.hcl"
  local fqdn="${VAULT_FQDN:-localhost}"
  local scheme
  scheme="$(vault_scheme)"
  local tls_disable="${TLS_DISABLE:-false}"
  local log_level="${LOG_LEVEL:-info}"

  if [ "$tls_disable" = "true" ]; then
    warn "TLS is disabled. This is NOT recommended for HA clusters."
    warn "Cluster communication requires TLS for security."
  fi

  if [ ! -f "$template" ]; then
    error "Template not found: ${template}"
    error "UNSEAL_METHOD must be 'shamir' or 'awskms'"
    exit 1
  fi

  cp "$template" config/vault.hcl

  # Replace common placeholders
  sed -i.bak "s|VAULT_API_ADDR_PLACEHOLDER|${scheme}://${fqdn}:${VAULT_PORT:-8200}|g" config/vault.hcl
  sed -i.bak "s|VAULT_CLUSTER_ADDR_PLACEHOLDER|${scheme}://${fqdn}:${VAULT_CLUSTER_PORT:-8201}|g" config/vault.hcl
  sed -i.bak "s|TLS_DISABLE_PLACEHOLDER|${tls_disable}|g" config/vault.hcl
  sed -i.bak "s|LOG_LEVEL_PLACEHOLDER|${log_level}|g" config/vault.hcl
  sed -i.bak "s|VAULT_NODE_ID_PLACEHOLDER|${VAULT_NODE_ID:-vault-1}|g" config/vault.hcl

  # Replace HA cluster node addresses
  sed -i.bak "s|VAULT_NODE_1_API_ADDR_PLACEHOLDER|${VAULT_NODE_1_ADDR}|g" config/vault.hcl
  sed -i.bak "s|VAULT_NODE_2_API_ADDR_PLACEHOLDER|${VAULT_NODE_2_ADDR}|g" config/vault.hcl
  sed -i.bak "s|VAULT_NODE_3_API_ADDR_PLACEHOLDER|${VAULT_NODE_3_ADDR}|g" config/vault.hcl

  if [ "$unseal" = "awskms" ]; then
    sed -i.bak "s|AWS_REGION_PLACEHOLDER|${AWS_REGION:-us-east-1}|g" config/vault.hcl
    sed -i.bak "s|AWS_KMS_KEY_ID_PLACEHOLDER|${AWS_KMS_KEY_ID:-REPLACE_ME}|g" config/vault.hcl
  fi

  rm -f config/vault.hcl.bak
  chmod 600 config/vault.hcl

  ok "Configuration generated: config/vault.hcl"
  info "  Node ID: ${VAULT_NODE_ID:-vault-1}"
  info "  Unseal:  ${unseal}"
  info "  Peers:   ${VAULT_NODE_1_ADDR}, ${VAULT_NODE_2_ADDR}, ${VAULT_NODE_3_ADDR}"
}

cmd_start() {
  info "Starting Vault container..."
  docker compose -f docker-compose.ha.yml --env-file .env up -d
  ok "Vault container started"
  info "Waiting for Vault to be ready..."
  sleep 3

  local addr
  addr="$(vault_addr)"
  for i in $(seq 1 10); do
    if curl_vault "${addr}/v1/sys/health" -o /dev/null 2>/dev/null; then
      ok "Vault is responding at ${addr}"
      return
    fi
    local code
    code=$(curl_vault -o /dev/null -w "%{http_code}" "${addr}/v1/sys/health" 2>/dev/null || echo "000")
    if [ "$code" = "501" ] || [ "$code" = "503" ] || [ "$code" = "200" ] || [ "$code" = "429" ]; then
      ok "Vault is responding at ${addr} (HTTP ${code})"
      return
    fi
    info "Waiting... (${i}/10)"
    sleep 2
  done
  error "Vault did not become ready. Check logs: docker compose -f docker-compose.ha.yml logs"
  exit 1
}

cmd_stop() {
  info "Stopping Vault container..."
  docker compose -f docker-compose.ha.yml --env-file .env down
  ok "Vault container stopped"
}

cmd_vault_init() {
  warn "This command should only be run on the FIRST node (node-1)."
  warn "Other nodes will automatically join via retry_join."
  echo ""

  local addr
  addr="$(vault_addr)"
  local shares="${KEY_SHARES:-5}"
  local threshold="${KEY_THRESHOLD:-3}"

  # Check if already initialized
  local init_status
  init_status=$(curl_vault "${addr}/v1/sys/health" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
  if [ "$init_status" = "200" ] || [ "$init_status" = "503" ] || [ "$init_status" = "429" ]; then
    warn "Vault is already initialized."
    return
  fi

  info "Initializing Vault cluster (shares=${shares}, threshold=${threshold})..."
  local result
  result=$(curl_vault -X POST \
    -d "{\"secret_shares\":${shares},\"secret_threshold\":${threshold}}" \
    "${addr}/v1/sys/init")

  echo "$result" > vault-init-keys.json
  chmod 600 vault-init-keys.json

  ok "Vault cluster initialized! Keys saved to vault-init-keys.json"
  echo ""
  echo -e "${RED}===========================================================${NC}"
  echo -e "${RED}  CRITICAL: Securely store vault-init-keys.json NOW!${NC}"
  echo -e "${RED}  It contains the unseal keys and root token.${NC}"
  echo -e "${RED}  Distribute unseal keys to different administrators.${NC}"
  echo -e "${RED}  Delete this file after securely backing up the keys.${NC}"
  echo -e "${RED}===========================================================${NC}"
  echo ""

  # Display root token
  local root_token
  root_token=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('root_token',''))" 2>/dev/null || echo "")
  if [ -n "$root_token" ]; then
    info "Root Token: ${root_token}"
  fi

  echo ""
  echo -e "${YELLOW}Next: Unseal this node, then unseal the other nodes.${NC}"
  echo -e "${YELLOW}The same unseal keys work on ALL nodes in the cluster.${NC}"
}

cmd_vault_unseal() {
  local addr
  addr="$(vault_addr)"
  local unseal="${UNSEAL_METHOD:-shamir}"

  if [ "$unseal" = "awskms" ]; then
    info "AWS KMS auto-unseal mode. Checking status..."
    local sealed
    sealed=$(curl_vault "${addr}/v1/sys/seal-status" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed','unknown'))" 2>/dev/null || echo "unknown")
    if [ "$sealed" = "False" ] || [ "$sealed" = "false" ]; then
      ok "Vault is already unsealed (auto-unseal via AWS KMS)"
    else
      warn "Vault is sealed. Check AWS KMS connectivity and credentials."
      warn "Container logs: docker compose -f docker-compose.ha.yml logs vault"
    fi
    return
  fi

  # Shamir unseal
  local threshold="${KEY_THRESHOLD:-3}"
  info "Shamir unseal: need ${threshold} key(s) to unseal"

  for i in $(seq 1 "$threshold"); do
    local sealed
    sealed=$(curl_vault "${addr}/v1/sys/seal-status" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed','unknown'))" 2>/dev/null || echo "unknown")
    if [ "$sealed" = "False" ] || [ "$sealed" = "false" ]; then
      ok "Vault is now unsealed!"
      return
    fi

    echo -n "Enter unseal key ${i}/${threshold}: "
    read -r -s unseal_key
    echo ""

    curl_vault -X POST \
      -d "{\"key\":\"${unseal_key}\"}" \
      "${addr}/v1/sys/unseal" > /dev/null 2>&1
  done

  # Final check — on HA followers, unseal completes asynchronously: after the
  # last key is submitted, a follower still has to finish the Raft join
  # handshake with the leader before seal-status flips to false. The leader
  # unseals synchronously, which is why it alone passed a single immediate
  # check. Poll for a short window instead of checking once.
  local sealed
  for i in $(seq 1 15); do
    sealed=$(curl_vault "${addr}/v1/sys/seal-status" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed','unknown'))" 2>/dev/null || echo "unknown")
    if [ "$sealed" = "False" ] || [ "$sealed" = "false" ]; then
      ok "Vault is now unsealed!"
      return
    fi
    info "Waiting for unseal to complete... (${i}/15)"
    sleep 2
  done

  error "Vault is still sealed. Please verify your unseal keys."
  error "If this is a follower still joining the Raft cluster, wait a moment"
  error "and re-check with: ./setup-ha.sh status"
  exit 1
}

cmd_register_plugin() {
  warn "Run this on the LEADER node only. Followers will sync automatically."
  echo ""

  local addr
  addr="$(vault_addr)"
  local plugin_name="${PLUGIN_NAME:-vault-plugin-crypto}"
  local plugin_version="${PLUGIN_VERSION:-v0.2.0}"
  local plugin_binary="${plugin_name}-${plugin_version}"
  local mount_path="${PLUGIN_MOUNT_PATH:-crypto}"

  # Get root token
  echo -n "Enter Vault root token: "
  read -r -s vault_token
  echo ""

  # Calculate SHA256
  info "Calculating plugin SHA256..."
  local sha256
  sha256=$(shasum -a 256 "plugins/${plugin_binary}" | cut -d ' ' -f1)
  info "SHA256: ${sha256}"

  # Register plugin
  info "Registering plugin ${plugin_name} ${plugin_version}..."
  local reg_result
  reg_result=$(curl_vault -X POST \
    -H "X-Vault-Token: ${vault_token}" \
    -d "{\"sha256\":\"${sha256}\",\"command\":\"${plugin_binary}\",\"version\":\"${plugin_version}\"}" \
    "${addr}/v1/sys/plugins/catalog/secret/${plugin_name}")

  if echo "$reg_result" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'errors' in d else 1)" 2>/dev/null; then
    error "Plugin registration failed:"
    echo "$reg_result" | python3 -m json.tool 2>/dev/null || echo "$reg_result"
    exit 1
  fi
  ok "Plugin registered"

  # Enable plugin
  info "Enabling plugin at /${mount_path}..."
  local enable_result
  enable_result=$(curl_vault -X POST \
    -H "X-Vault-Token: ${vault_token}" \
    -d "{\"type\":\"${plugin_name}\",\"plugin_version\":\"${plugin_version}\",\"description\":\"Cryptographic key management for blockchain applications\"}" \
    "${addr}/v1/sys/mounts/${mount_path}")

  if echo "$enable_result" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'errors' in d else 1)" 2>/dev/null; then
    error "Plugin enable failed:"
    echo "$enable_result" | python3 -m json.tool 2>/dev/null || echo "$enable_result"
    exit 1
  fi
  ok "Plugin enabled at /${mount_path}"

  # Verify
  info "Verifying plugin mount..."
  local tune_result
  tune_result=$(curl_vault -X GET \
    -H "X-Vault-Token: ${vault_token}" \
    "${addr}/v1/sys/mounts/${mount_path}/tune")
  local mounted_version
  mounted_version=$(echo "$tune_result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('plugin_version','unknown'))" 2>/dev/null || echo "unknown")
  ok "Mounted plugin version: ${mounted_version}"
}

cmd_status() {
  local addr
  addr="$(vault_addr)"

  echo -e "\n${YELLOW}=== Vault Node Status (${VAULT_NODE_ID:-unknown}) ===${NC}\n"

  # Container status
  info "Container:"
  local container="${VAULT_CONTAINER_NAME:-vault-ha-1}"
  if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
    ok "  ${container} is running"
  else
    error "  ${container} is NOT running"
    return
  fi

  # Vault health
  info "Vault:"
  local health_code
  health_code=$(curl_vault -o /dev/null -w "%{http_code}" "${addr}/v1/sys/health" 2>/dev/null || echo "000")
  case "$health_code" in
    200) ok "  Status: active (leader)" ;;
    429) ok "  Status: standby (follower)" ;;
    472) warn "  Status: disaster recovery secondary" ;;
    473) ok "  Status: performance standby" ;;
    501) warn "  Status: not initialized" ;;
    503) warn "  Status: sealed" ;;
    *)   error "  Status: unreachable (HTTP ${health_code})" ;;
  esac

  # Seal status
  local seal_info
  seal_info=$(curl_vault "${addr}/v1/sys/seal-status" 2>/dev/null || echo "{}")
  local sealed
  sealed=$(echo "$seal_info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed','unknown'))" 2>/dev/null || echo "unknown")
  local seal_type
  seal_type=$(echo "$seal_info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('type','unknown'))" 2>/dev/null || echo "unknown")
  local cluster_name
  cluster_name=$(echo "$seal_info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cluster_name','unknown'))" 2>/dev/null || echo "unknown")
  info "  Node ID:      ${VAULT_NODE_ID:-unknown}"
  info "  Sealed:       ${sealed}"
  info "  Seal type:    ${seal_type}"
  info "  Cluster:      ${cluster_name}"

  echo ""
}

cmd_raft_status() {
  local addr
  addr="$(vault_addr)"

  echo -e "\n${YELLOW}=== Raft Cluster Status ===${NC}\n"

  # Get token
  local vault_token="${VAULT_TOKEN:-}"
  if [ -z "$vault_token" ]; then
    echo -n "Enter Vault token: "
    read -r -s vault_token
    echo ""
  fi

  local result
  result=$(curl_vault -X GET \
    -H "X-Vault-Token: ${vault_token}" \
    "${addr}/v1/sys/storage/raft/configuration" 2>/dev/null)

  if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'errors' in d else 1)" 2>/dev/null; then
    error "Failed to get Raft status. Check your token or try from the leader node."
    echo "$result" | python3 -m json.tool 2>/dev/null || echo "$result"
    return
  fi

  # Parse and display cluster members
  python3 -c "
import sys, json
data = json.load(sys.stdin)
servers = data.get('data', {}).get('config', {}).get('servers', [])
if not servers:
    print('  No Raft peers found.')
    sys.exit(0)
print(f'  Total nodes: {len(servers)}')
print()
print(f'  {\"Node ID\":<20} {\"Address\":<35} {\"Voter\":<8} {\"Leader\"}')
print(f'  {\"-\"*20} {\"-\"*35} {\"-\"*8} {\"-\"*8}')
for s in servers:
    node_id = s.get('node_id', 'unknown')
    addr = s.get('address', 'unknown')
    voter = 'yes' if s.get('voter', False) else 'no'
    leader = '<-- leader' if s.get('leader', False) else ''
    print(f'  {node_id:<20} {addr:<35} {voter:<8} {leader}')
" <<< "$result" 2>/dev/null || echo "$result" | python3 -m json.tool 2>/dev/null || echo "$result"

  echo ""
}

cmd_gen_backup_token() {
  local addr
  addr="$(vault_addr)"
  local policy_name="raft-snapshot"
  local token_file="backups/backup.token"
  local policy_only=false
  [ "${1:-}" = "--policy-only" ] && policy_only=true

  if [ "$policy_only" = true ]; then
    info "Rewriting policy '${policy_name}' only; no new token will be created."
  else
    info "Generating a least-privilege backup token via the Vault API (no vault CLI needed)..."
  fi

  # Root token (or any token with sudo on auth/token/create): prefer env, else prompt
  local vault_token="${VAULT_TOKEN:-}"
  if [ -z "$vault_token" ]; then
    echo -n "Enter Vault root token: "
    read -r -s vault_token
    echo ""
  fi
  if [ -z "$vault_token" ]; then
    error "No token provided."
    exit 1
  fi

  # 1. Write the least-privilege policy: read Raft snapshots + inspect and renew
  #    own token. lookup-self and renew-self are NOT ACL-exempt -- they are
  #    granted by the built-in `default` policy, which this token opts out of via
  #    no_default_policy, so they must be granted explicitly here.
  info "Writing policy '${policy_name}' (snapshot read + lookup-self + renew-self)..."
  local policy_hcl='path "sys/storage/raft/snapshot" {
  capabilities = ["read"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}'
  local policy_payload
  policy_payload=$(printf '%s' "$policy_hcl" | python3 -c 'import json,sys; print(json.dumps({"policy": sys.stdin.read()}))')

  local code
  # curl already emits "000" via -w on connection failure; do not append another.
  code=$(curl_vault -X PUT \
    -H "X-Vault-Token: ${vault_token}" \
    -d "$policy_payload" \
    -o /dev/null -w "%{http_code}" \
    "${addr}/v1/sys/policies/acl/${policy_name}" 2>/dev/null || true)
  code="${code:-000}"
  if [ "$code" != "204" ] && [ "$code" != "200" ]; then
    error "Failed to write policy '${policy_name}' (HTTP ${code})."
    error "The token needs permission to write sys/policies/acl (root or equivalent)."
    exit 1
  fi
  ok "Policy '${policy_name}' written"

  # Policies are resolved by name on every request, so rewriting the policy is
  # enough to fix an already-issued token -- no need to mint a replacement.
  if [ "$policy_only" = true ]; then
    echo ""
    ok "Existing tokens bound to '${policy_name}' picked up the new rules immediately."
    info "Verify with: ./setup-ha.sh token-status --backup-token"
    return
  fi

  # 2. Create an orphan, periodic token bound to that policy, with no default policy.
  #    no_parent  -> survives revocation of the root token used here (orphan)
  #    period     -> periodic token, renewable indefinitely, never hits a max TTL
  info "Creating periodic backup token (period=720h, orphan, no default policy)..."
  local create_payload
  create_payload='{"policies":["'"${policy_name}"'"],"period":"720h","no_parent":true,"no_default_policy":true,"display_name":"raft-snapshot-backup","meta":{"purpose":"automated-raft-snapshot-backup"}}'
  local resp
  resp=$(curl_vault -X POST \
    -H "X-Vault-Token: ${vault_token}" \
    -d "$create_payload" \
    "${addr}/v1/auth/token/create" 2>/dev/null || echo "")

  local backup_token
  backup_token=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('auth',{}).get('client_token',''))" 2>/dev/null || echo "")
  if [ -z "$backup_token" ]; then
    error "Token creation failed. Vault response:"
    echo "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"
    exit 1
  fi

  # 3. Persist with tight permissions, then display.
  mkdir -p backups
  ( umask 077; printf '%s' "$backup_token" > "$token_file" )
  chmod 600 "$token_file"

  ok "Backup token created and saved to ${token_file} (mode 600)"
  echo ""
  info "Token: ${backup_token}"
  echo ""
  echo -e "${YELLOW}Next steps:${NC}"
  echo "  - Unattended backup:  VAULT_TOKEN=\$(cat ${token_file}) ./setup-ha.sh backup"
  echo "  - Check its TTL:      ./setup-ha.sh token-status --backup-token"
  echo "  - This token is periodic (720h); renew it on a schedule so it never expires."
  echo "  - Full crontab example (renew + backup): see DEPLOY_HA.md -> 自动备份"
}

cmd_token_status() {
  local addr
  addr="$(vault_addr)"
  local token_file="backups/backup.token"

  # Token source: --backup-token reads the saved backup token, VAULT_TOKEN wins
  # over the prompt. Never accept a token as a positional argument: it would be
  # visible in `ps` output and land in shell history.
  local vault_token=""
  if [ "${1:-}" = "--backup-token" ]; then
    if [ ! -f "$token_file" ]; then
      error "Backup token not found: ${token_file}"
      error "Create one with: ./setup-ha.sh gen-backup-token"
      exit 1
    fi
    vault_token=$(cat "$token_file")
    info "Using backup token from ${token_file}"
  else
    vault_token="${VAULT_TOKEN:-}"
    if [ -z "$vault_token" ]; then
      echo -n "Enter Vault token to inspect: "
      read -r -s vault_token
      echo ""
    fi
  fi
  if [ -z "$vault_token" ]; then
    error "No token provided."
    exit 1
  fi

  # lookup-self is NOT ACL-exempt: read access comes from the built-in `default`
  # policy. A token created with no_default_policy needs it granted explicitly.
  local tmp http_code body
  tmp=$(mktemp)
  # On a connection failure curl already emits "000" via -w, so do not append
  # another one with `|| echo 000` -- that yields the unmatchable "000\n000".
  http_code=$(curl_vault -X GET \
    -H "X-Vault-Token: ${vault_token}" \
    -o "$tmp" -w "%{http_code}" \
    "${addr}/v1/auth/token/lookup-self" 2>/dev/null || true)
  http_code="${http_code:-000}"
  body=$(cat "$tmp")
  rm -f "$tmp"

  case "$http_code" in
    200) ;;
    403)
      # Vault returns the same "permission denied" for a bad token and for a
      # valid token lacking read on auth/token/lookup-self, so name both causes.
      error "HTTP 403 on auth/token/lookup-self. Either:"
      error "  a) the token is invalid, expired or revoked; or"
      error "  b) the token's policy does not grant read on auth/token/lookup-self."
      error "     (b) applies to backup tokens issued before that rule was added."
      error "     Fix without reissuing the token: ./setup-ha.sh gen-backup-token --policy-only"
      exit 1
      ;;
    503)
      error "Vault is sealed (HTTP 503). Unseal first: ./setup-ha.sh vault-unseal"
      exit 1
      ;;
    000)
      error "Cannot reach Vault at ${addr}. Is the container running?"
      exit 1
      ;;
    *)
      error "Token lookup failed (HTTP ${http_code})."
      echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
      exit 1
      ;;
  esac

  echo -e "\n${YELLOW}=== Token Status ===${NC}\n"
  printf '%s' "$body" | python3 -c '
import sys, json

d = json.load(sys.stdin).get("data", {})

def human(secs):
    if secs <= 0:
        return "0s"
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, sec = divmod(rem, 60)
    parts = []
    if days:  parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    if mins:  parts.append(f"{mins}m")
    if not parts: parts.append(f"{sec}s")
    return " ".join(parts)

ttl        = d.get("ttl", 0)
period     = d.get("period", 0)
max_ttl    = d.get("explicit_max_ttl", 0)
renewable  = d.get("renewable", False)
expire     = d.get("expire_time")
policies   = d.get("policies", [])
num_uses   = d.get("num_uses", 0)

name     = d.get("display_name") or "-"
accessor = d.get("accessor") or "-"
pol_str  = ", ".join(policies) if policies else "-"
orphan   = d.get("orphan", False)
issued   = d.get("issue_time") or "-"

print(f"  Display name:  {name}")
print(f"  Accessor:      {accessor}")
print(f"  Policies:      {pol_str}")
print(f"  Orphan:        {orphan}")
print(f"  Renewable:     {renewable}")
print(f"  Issued at:     {issued}")
print()

if expire is None:
    print("  TTL:           never expires (root token or period-less service token)")
else:
    print(f"  TTL remaining: {human(ttl)}  ({ttl}s)")
    print(f"  Expires at:    {expire}")

if period:
    print(f"  Period:        {human(period)}  (renew-self resets TTL back to this)")
max_ttl_str = human(max_ttl) if max_ttl else "unlimited (no explicit max)"
print(f"  Max TTL:       {max_ttl_str}")
if num_uses:
    print(f"  Uses left:     {num_uses}")

warnings = []
if expire is not None and ttl <= 0:
    warnings.append("Token has already expired.")
elif expire is not None and ttl < 86400:
    warnings.append(f"Expires in under 24h ({human(ttl)}). Renew it now.")
if period and renewable and ttl < period // 2:
    warnings.append("TTL is below half the period - scheduled renew-self is likely failing. "
                    "Check logs/backup.log for: token renew-self failed")
if expire is not None and not renewable:
    warnings.append("Token is NOT renewable; it will expire and cannot be extended.")

if warnings:
    print()
    for w in warnings:
        print(f"  [WARN] {w}")
'
  echo ""
}

cmd_backup() {
  local addr
  addr="$(vault_addr)"
  local backup_dir="backups"
  local timestamp
  timestamp=$(date +%Y%m%d_%H%M%S)
  local backup_file="${backup_dir}/vault-backup-${timestamp}.snap"

  mkdir -p "$backup_dir"

  # Check Vault is unsealed
  local sealed
  sealed=$(curl_vault "${addr}/v1/sys/seal-status" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed','unknown'))" 2>/dev/null || echo "unknown")
  if [ "$sealed" != "False" ] && [ "$sealed" != "false" ]; then
    error "Vault is sealed or unreachable. Cannot create snapshot."
    exit 1
  fi

  # Get token
  local vault_token="${VAULT_TOKEN:-}"
  if [ -z "$vault_token" ]; then
    echo -n "Enter Vault token (root or with sys/storage/raft/snapshot access): "
    read -r -s vault_token
    echo ""
  fi

  info "Creating Raft snapshot..."
  local http_code
  http_code=$(curl_vault -X GET \
    -H "X-Vault-Token: ${vault_token}" \
    -o "${backup_file}" \
    -w "%{http_code}" \
    "${addr}/v1/sys/storage/raft/snapshot" 2>/dev/null)

  if [ "$http_code" = "200" ] && [ -s "$backup_file" ]; then
    local size
    size=$(du -h "$backup_file" | cut -f1)
    ok "Snapshot saved: ${backup_file} (${size})"
    info "To restore: ./setup-ha.sh restore ${backup_file}"
  else
    rm -f "$backup_file"
    error "Snapshot failed (HTTP ${http_code}). Check your token permissions."
    error "Required policy: path \"sys/storage/raft/snapshot\" { capabilities = [\"read\"] }"
    exit 1
  fi
}

# Shared implementation for `restore` and `restore-force`.
#
# restore       -> sys/storage/raft/snapshot
#                  Vault verifies the snapshot's sealed hash file against the
#                  current seal, which rejects a snapshot from a *different*
#                  cluster. Correct for rolling back data within one cluster.
# restore-force -> sys/storage/raft/snapshot-force
#                  Bypasses that check. Required to rebuild a destroyed cluster
#                  on fresh servers, where the new cluster's Shamir keys cannot
#                  match the snapshot's. Afterwards every node seals itself and
#                  must be unsealed with the ORIGINAL cluster's unseal keys.
_restore_snapshot() {
  local snapshot_file="$1"
  local force="$2"

  local endpoint="sys/storage/raft/snapshot"
  [ "$force" = true ] && endpoint="sys/storage/raft/snapshot-force"

  if [ -z "$snapshot_file" ]; then
    if [ "$force" = true ]; then
      error "Usage: ./setup-ha.sh restore-force <snapshot-file>"
    else
      error "Usage: ./setup-ha.sh restore <snapshot-file>"
    fi
    error "Example: backups/vault-backup-20250215_120000.snap"
    exit 1
  fi

  if [ ! -f "$snapshot_file" ]; then
    error "Snapshot file not found: ${snapshot_file}"
    exit 1
  fi

  local addr
  addr="$(vault_addr)"

  # Check Vault is unsealed
  local sealed
  sealed=$(curl_vault "${addr}/v1/sys/seal-status" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed','unknown'))" 2>/dev/null || echo "unknown")
  if [ "$sealed" != "False" ] && [ "$sealed" != "false" ]; then
    error "Vault is sealed or unreachable. Unseal first, then restore."
    exit 1
  fi

  # Get token
  local vault_token="${VAULT_TOKEN:-}"
  if [ -z "$vault_token" ]; then
    echo -n "Enter Vault token (root or with sys/storage/raft/snapshot access): "
    read -r -s vault_token
    echo ""
  fi

  local size
  size=$(du -h "$snapshot_file" | cut -f1)
  warn "This will OVERWRITE all Vault data with snapshot: ${snapshot_file} (${size})"
  warn "This affects the ENTIRE cluster, not just this node."

  local confirm
  if [ "$force" = true ]; then
    echo ""
    warn "FORCE mode: the seal-consistency check is bypassed."
    warn "Only use this to rebuild a destroyed cluster on fresh servers."
    warn "After the restore ALL nodes will seal. You will then need the"
    warn "ORIGINAL cluster's unseal keys -- the ones matching this snapshot."
    warn "Without them the restored data is unrecoverable."
    echo ""
    echo -n "Type FORCE to proceed: "
    read -r confirm
    if [ "$confirm" != "FORCE" ]; then
      info "Restore cancelled."
      return
    fi
  else
    echo -n "Are you sure? (yes/no): "
    read -r confirm
    if [ "$confirm" != "yes" ]; then
      info "Restore cancelled."
      return
    fi
  fi

  info "Restoring from Raft snapshot via ${endpoint}..."
  local tmp http_code body
  tmp=$(mktemp)
  http_code=$(curl_vault -X POST \
    -H "X-Vault-Token: ${vault_token}" \
    --data-binary @"${snapshot_file}" \
    -o "$tmp" -w "%{http_code}" \
    "${addr}/v1/${endpoint}" 2>/dev/null || true)
  http_code="${http_code:-000}"
  body=$(cat "$tmp")
  rm -f "$tmp"

  if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
    ok "Snapshot restored successfully!"
    if [ "$force" = true ]; then
      echo ""
      warn "Every node is now sealed. Unseal all 3 with the ORIGINAL cluster's"
      warn "unseal keys (not the ones from the temporary cluster's vault-init)."
      info "On each node: ./setup-ha.sh vault-unseal"
      info "Then verify:  ./setup-ha.sh raft-status && ./setup-ha.sh list-keys"
    else
      warn "Vault will restart automatically. You may need to unseal all nodes again (Shamir mode)."
      info "Run: ./setup-ha.sh status"
    fi
    return
  fi

  error "Restore failed (HTTP ${http_code})."
  [ -n "$body" ] && { echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"; }

  # Vault's own hint when the snapshot belongs to a different cluster.
  if [ "$force" != true ] && echo "$body" | grep -q "snapshot-force"; then
    echo ""
    error "This snapshot was taken from a cluster with different unseal keys."
    error "To rebuild a destroyed cluster on fresh servers, use:"
    error "  ./setup-ha.sh restore-force ${snapshot_file}"
    error "See DEPLOY_HA.md -> 灾难恢复 before doing so."
  else
    error "Required policy: path \"sys/storage/raft/snapshot\" { capabilities = [\"create\", \"update\"] }"
  fi
  exit 1
}

cmd_restore() {
  _restore_snapshot "${1:-}" false
}

cmd_restore_force() {
  _restore_snapshot "${1:-}" true
}

# ---- Crypto plugin inspection (useful to verify a restore) ----

cmd_list_keys() {
  local addr mount_path
  addr="$(vault_addr)"
  mount_path="${PLUGIN_MOUNT_PATH:-crypto}"

  local vault_token="${VAULT_TOKEN:-}"
  if [ -z "$vault_token" ]; then
    echo -n "Enter Vault token: "
    read -r -s vault_token
    echo ""
  fi

  local tmp http_code body
  tmp=$(mktemp)
  http_code=$(curl_vault -X GET \
    -H "X-Vault-Token: ${vault_token}" \
    -o "$tmp" -w "%{http_code}" \
    "${addr}/v1/${mount_path}/keys?list=true" 2>/dev/null || true)
  http_code="${http_code:-000}"
  body=$(cat "$tmp")
  rm -f "$tmp"

  case "$http_code" in
    200) ;;
    # Vault returns 404 for an empty LIST, which is not an error here.
    404)
      echo -e "\n${YELLOW}=== Crypto Keys (mount: ${mount_path}) ===${NC}\n"
      info "  No keys found (the mount exists but holds no keys)."
      echo ""
      return
      ;;
    403)
      error "Permission denied (HTTP 403). The token needs list on ${mount_path}/keys."
      exit 1
      ;;
    503)
      error "Vault is sealed (HTTP 503). Unseal first: ./setup-ha.sh vault-unseal"
      exit 1
      ;;
    000)
      error "Cannot reach Vault at ${addr}. Is the container running?"
      exit 1
      ;;
    *)
      error "Failed to list keys (HTTP ${http_code})."
      error "Is the plugin mounted at '${mount_path}'? Check: ./setup-ha.sh status"
      [ -n "$body" ] && { echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"; }
      exit 1
      ;;
  esac

  echo -e "\n${YELLOW}=== Crypto Keys (mount: ${mount_path}) ===${NC}\n"
  printf '%s' "$body" | python3 -c '
import sys, json
keys = json.load(sys.stdin).get("data", {}).get("keys", [])
print(f"  Total keys: {len(keys)}")
print()
for k in keys:
    print(f"  {k}")
'
  echo ""
  info "Inspect one key: ./setup-ha.sh key-info <external_id>"
}

cmd_key_info() {
  local external_id="$1"
  if [ -z "$external_id" ]; then
    error "Usage: ./setup-ha.sh key-info <external_id>"
    error "List available IDs with: ./setup-ha.sh list-keys"
    exit 1
  fi

  local addr mount_path
  addr="$(vault_addr)"
  mount_path="${PLUGIN_MOUNT_PATH:-crypto}"

  local vault_token="${VAULT_TOKEN:-}"
  if [ -z "$vault_token" ]; then
    echo -n "Enter Vault token: "
    read -r -s vault_token
    echo ""
  fi

  local tmp http_code body
  tmp=$(mktemp)
  http_code=$(curl_vault -X GET \
    -H "X-Vault-Token: ${vault_token}" \
    -o "$tmp" -w "%{http_code}" \
    "${addr}/v1/${mount_path}/keys/${external_id}" 2>/dev/null || true)
  http_code="${http_code:-000}"
  body=$(cat "$tmp")
  rm -f "$tmp"

  if [ "$http_code" != "200" ]; then
    error "Failed to read key '${external_id}' (HTTP ${http_code})."
    [ -n "$body" ] && { echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"; }
    exit 1
  fi

  echo -e "\n${YELLOW}=== Key: ${external_id} ===${NC}\n"
  printf '%s' "$body" | python3 -c '
import sys, json
d = json.load(sys.stdin).get("data", {})
meta = d.get("metadata") or {}
name    = d.get("name") or "-"
ext_id  = d.get("external_id") or "-"
curve   = d.get("curve") or "-"
pub_key = d.get("public_key") or "-"
created = d.get("created_at") or "-"
print(f"  Name:        {name}")
print(f"  External ID: {ext_id}")
print(f"  Curve:       {curve}")
print(f"  Public key:  {pub_key}")
print(f"  Created at:  {created}")
if meta:
    print("  Metadata:")
    for k, v in meta.items():
        print(f"    {k}: {v}")
'
  echo ""
  # The plugin derives public_key from the stored private key on every read, so a
  # successful read proves the key material decrypted correctly after a restore.
  ok "Public key derived from stored private key -- key material decrypts correctly."
}

cmd_help() {
  echo "Vault Crypto Plugin - HA Cluster Deployment Helper"
  echo ""
  echo "Usage: $0 <command>"
  echo ""
  echo "Setup (run in order for first deployment):"
  echo "  init-dirs       Create required directory structure"
  echo "  gen-ca          Generate CA certificate (run once, distribute to all nodes)"
  echo "  gen-cert        Generate node TLS certificate using shared CA"
  echo "  prepare-config  Generate vault.hcl from .env settings"
  echo ""
  echo "Lifecycle:"
  echo "  start           Start Vault container on this node"
  echo "  stop            Stop Vault container on this node"
  echo "  vault-init      Initialize Vault cluster (run on node-1 only)"
  echo "  vault-unseal    Unseal Vault on this node (Shamir mode)"
  echo "  register-plugin Register and enable the crypto plugin (run on leader only)"
  echo ""
  echo "Operations:"
  echo "  status           Show this node's Vault status"
  echo "  raft-status      Show Raft cluster member list"
  echo "  gen-backup-token Create a least-privilege token for unattended backups"
  echo "                   (--policy-only rewrites the policy, keeps the existing token)"
  echo "  token-status     Show a token's TTL and policies (add --backup-token to read backups/backup.token)"
  echo "  backup           Create a Raft snapshot backup (online, no downtime)"
  echo "  restore          Restore a snapshot into THIS cluster (seal check enforced)"
  echo "  list-keys        List crypto plugin keys (verifies the plugin mount)"
  echo "  key-info         Show one key by external_id (verifies key material decrypts)"
  echo ""
  echo "Disaster recovery:"
  echo "  restore-force    Restore a snapshot into a FRESH cluster (bypasses seal check)"
  echo "                   Requires the ORIGINAL cluster's unseal keys afterwards."
  echo "                   See DEPLOY_HA.md -> 灾难恢复"
  echo ""
  echo "  help             Show this help message"
}

# ==================== Main ====================

COMMAND="${1:-help}"

# Load .env for most commands (except help and init-dirs)
case "$COMMAND" in
  help) ;;
  init-dirs)
    [ -f .env ] && load_env || true
    ;;
  gen-ca) ;;
  *)
    load_env
    ;;
esac

case "$COMMAND" in
  init-dirs)       cmd_init_dirs ;;
  gen-ca)          cmd_gen_ca ;;
  gen-cert)        cmd_gen_cert ;;
  prepare-config)  cmd_prepare_config ;;
  start)           cmd_start ;;
  stop)            cmd_stop ;;
  vault-init)      cmd_vault_init ;;
  vault-unseal)    cmd_vault_unseal ;;
  register-plugin) cmd_register_plugin ;;
  status)          cmd_status ;;
  raft-status)     cmd_raft_status ;;
  gen-backup-token) cmd_gen_backup_token "${2:-}" ;;
  token-status)    cmd_token_status "${2:-}" ;;
  backup)          cmd_backup ;;
  restore)         cmd_restore "${2:-}" ;;
  restore-force)   cmd_restore_force "${2:-}" ;;
  list-keys)       cmd_list_keys ;;
  key-info)        cmd_key_info "${2:-}" ;;
  help)            cmd_help ;;
  *)
    error "Unknown command: ${COMMAND}"
    cmd_help
    exit 1
    ;;
esac
