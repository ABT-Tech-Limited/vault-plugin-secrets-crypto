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
#   backup          Create a Raft snapshot backup (online, no downtime)
#   restore         Restore Vault from a Raft snapshot
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
  local plugin_binary="${PLUGIN_NAME:-vault-plugin-crypto}-${PLUGIN_VERSION:-v0.1.0}"
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

  # Collect all node FQDNs for SAN
  local san="DNS:${fqdn},DNS:localhost,IP:127.0.0.1"

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
  info "  Cert: tls/cert.pem (SAN: ${fqdn}, localhost, 127.0.0.1)"
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

  # Final check
  local sealed
  sealed=$(curl_vault "${addr}/v1/sys/seal-status" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed','unknown'))" 2>/dev/null || echo "unknown")
  if [ "$sealed" = "False" ] || [ "$sealed" = "false" ]; then
    ok "Vault is now unsealed!"
  else
    error "Vault is still sealed. Please verify your unseal keys."
    exit 1
  fi
}

cmd_register_plugin() {
  warn "Run this on the LEADER node only. Followers will sync automatically."
  echo ""

  local addr
  addr="$(vault_addr)"
  local plugin_name="${PLUGIN_NAME:-vault-plugin-crypto}"
  local plugin_version="${PLUGIN_VERSION:-v0.1.0}"
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

cmd_restore() {
  local snapshot_file="${2:-}"
  if [ -z "$snapshot_file" ]; then
    error "Usage: ./setup-ha.sh restore <snapshot-file>"
    error "Example: ./setup-ha.sh restore backups/vault-backup-20250215_120000.snap"
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
  echo -n "Are you sure? (yes/no): "
  read -r confirm
  if [ "$confirm" != "yes" ]; then
    info "Restore cancelled."
    return
  fi

  info "Restoring from Raft snapshot..."
  local http_code
  http_code=$(curl_vault -X POST \
    -H "X-Vault-Token: ${vault_token}" \
    --data-binary @"${snapshot_file}" \
    -o /dev/null \
    -w "%{http_code}" \
    "${addr}/v1/sys/storage/raft/snapshot" 2>/dev/null)

  if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
    ok "Snapshot restored successfully!"
    warn "Vault will restart automatically. You may need to unseal all nodes again (Shamir mode)."
    info "Run: ./setup-ha.sh status"
  else
    error "Restore failed (HTTP ${http_code}). Check your token permissions."
    error "Required policy: path \"sys/storage/raft/snapshot\" { capabilities = [\"create\", \"update\"] }"
    exit 1
  fi
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
  echo "  status          Show this node's Vault status"
  echo "  raft-status     Show Raft cluster member list"
  echo "  backup          Create a Raft snapshot backup (online, no downtime)"
  echo "  restore         Restore Vault from a Raft snapshot"
  echo "  help            Show this help message"
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
  backup)          cmd_backup ;;
  restore)         cmd_restore "$@" ;;
  help)            cmd_help ;;
  *)
    error "Unknown command: ${COMMAND}"
    cmd_help
    exit 1
    ;;
esac
