#!/usr/bin/env bash
# Vault Crypto Plugin - Deployment Helper Script
#
# Usage: ./setup.sh <command>
#
# Commands:
#   check-deps      Check required dependencies
#   install-deps    Install missing dependencies (Docker, Go, openssl, etc.)
#   init-dirs       Create required directory structure
#   gen-tls         Generate self-signed TLS certificates (testing only)
#   prepare-config  Generate vault.hcl from .env settings
#   start           Start Vault container
#   stop            Stop Vault container
#   vault-init      Initialize Vault (first time only)
#                   (shamir: unseal keys; awskms: recovery keys + auto-unseal)
#   vault-unseal    Unseal Vault (Shamir; status check for awskms)
#   register-plugin Register and enable the crypto plugin
#   gen-app-token   Create a least-privilege app token for the crypto plugin API
#   token-status    Show a token's TTL, policies and renewal health
#   status          Show Vault and plugin status
#   backup          Create a Raft snapshot backup (online, no downtime)
#   restore         Restore Vault from a Raft snapshot
#   all             Run full first-time deployment
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

# Read root token from vault-init-keys.json (or prompt interactively)
read_root_token() {
  local token="${1:-}"
  if [ -n "$token" ]; then
    echo "$token"
    return
  fi
  if [ -f vault-init-keys.json ]; then
    token=$(python3 -c "import sys,json; print(json.load(open('vault-init-keys.json')).get('root_token',''))" 2>/dev/null || echo "")
    if [ -n "$token" ]; then
      echo "$token"
      return
    fi
  fi
  # Fallback: interactive prompt
  echo -n "Enter Vault root token: " >&2
  read -r -s token
  echo "" >&2
  echo "$token"
}

# ==================== Commands ====================

# Detect OS and architecture
detect_os() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in
    x86_64)  arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
  esac
  echo "${os} ${arch}"
}

# Get required Go version (from .env or go.mod)
required_go_version() {
  local ver="${GO_VERSION:-}"
  if [ -z "$ver" ] && [ -f ../go.mod ]; then
    ver=$(grep '^go ' ../go.mod | awk '{print $2}')
  fi
  echo "${ver:-}"
}

# Compare semver: returns 0 if $1 >= $2
version_gte() {
  [ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

cmd_check_deps() {
  info "Checking dependencies..."
  local missing=0

  # Docker
  if command -v docker &>/dev/null; then
    local docker_ver
    docker_ver=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    ok "Docker: ${docker_ver}"
  else
    error "Docker: not found"
    missing=$((missing + 1))
  fi

  # Docker Compose V2
  if docker compose version &>/dev/null; then
    local compose_ver
    compose_ver=$(docker compose version --short 2>/dev/null || echo "unknown")
    ok "Docker Compose: ${compose_ver}"
  else
    error "Docker Compose V2: not found"
    missing=$((missing + 1))
  fi

  # openssl
  if command -v openssl &>/dev/null; then
    local ssl_ver
    ssl_ver=$(openssl version 2>/dev/null | awk '{print $2}')
    ok "OpenSSL: ${ssl_ver}"
  else
    error "OpenSSL: not found"
    missing=$((missing + 1))
  fi

  # curl
  if command -v curl &>/dev/null; then
    local curl_ver
    curl_ver=$(curl --version 2>/dev/null | head -1 | awk '{print $2}')
    ok "curl: ${curl_ver}"
  else
    error "curl: not found"
    missing=$((missing + 1))
  fi

  # python3
  if command -v python3 &>/dev/null; then
    local py_ver
    py_ver=$(python3 --version 2>/dev/null | awk '{print $2}')
    ok "Python3: ${py_ver}"
  else
    error "Python3: not found"
    missing=$((missing + 1))
  fi

  # Go
  local required_go
  required_go=$(required_go_version)
  if command -v go &>/dev/null; then
    local go_ver
    go_ver=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
    if [ -n "$required_go" ]; then
      if version_gte "$go_ver" "$required_go"; then
        ok "Go: ${go_ver} (required: ${required_go})"
      else
        warn "Go: ${go_ver} (required: ${required_go}, upgrade needed)"
        missing=$((missing + 1))
      fi
    else
      ok "Go: ${go_ver}"
    fi
  else
    if [ -n "$required_go" ]; then
      error "Go: not found (required: ${required_go})"
    else
      error "Go: not found"
    fi
    missing=$((missing + 1))
  fi

  # jq (optional)
  if command -v jq &>/dev/null; then
    local jq_ver
    jq_ver=$(jq --version 2>/dev/null | sed 's/jq-//')
    ok "jq: ${jq_ver} (optional)"
  else
    warn "jq: not found (optional, for JSON formatting)"
  fi

  echo ""
  if [ "$missing" -gt 0 ]; then
    error "${missing} required dependency(ies) missing."
    info "Run './setup.sh install-deps' to install them automatically."
    return 1
  else
    ok "All required dependencies are satisfied."
  fi
}

cmd_install_deps() {
  info "Installing missing dependencies..."
  local read_pair
  read_pair=$(detect_os)
  local os arch
  os=$(echo "$read_pair" | awk '{print $1}')
  arch=$(echo "$read_pair" | awk '{print $2}')
  info "Detected OS: ${os}, Arch: ${arch}"

  # Detect package manager
  local pkg_mgr=""
  if [ "$os" = "darwin" ]; then
    if command -v brew &>/dev/null; then
      pkg_mgr="brew"
    else
      error "Homebrew not found. Install from https://brew.sh"
      exit 1
    fi
  elif [ "$os" = "linux" ]; then
    if command -v apt-get &>/dev/null; then
      pkg_mgr="apt"
    elif command -v yum &>/dev/null; then
      pkg_mgr="yum"
    elif command -v dnf &>/dev/null; then
      pkg_mgr="dnf"
    elif command -v pacman &>/dev/null; then
      pkg_mgr="pacman"
    else
      error "No supported package manager found (apt/yum/dnf/pacman)."
      exit 1
    fi
  else
    error "Unsupported OS: ${os}"
    exit 1
  fi
  info "Package manager: ${pkg_mgr}"
  echo ""

  # Install Docker
  if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    case "$pkg_mgr" in
      brew)
        brew install --cask docker
        warn "Start Docker Desktop manually after installation."
        ;;
      apt)
        curl -fsSL https://get.docker.com | sh
        sudo systemctl enable --now docker
        sudo usermod -aG docker "$USER"
        warn "Log out and back in for docker group to take effect."
        ;;
      yum|dnf)
        curl -fsSL https://get.docker.com | sh
        sudo systemctl enable --now docker
        sudo usermod -aG docker "$USER"
        warn "Log out and back in for docker group to take effect."
        ;;
      pacman)
        sudo pacman -S --noconfirm docker docker-compose
        sudo systemctl enable --now docker
        sudo usermod -aG docker "$USER"
        ;;
    esac
    ok "Docker installed."
  fi

  # Install openssl
  if ! command -v openssl &>/dev/null; then
    info "Installing OpenSSL..."
    case "$pkg_mgr" in
      brew)    brew install openssl ;;
      apt)     sudo apt-get install -y openssl ;;
      yum|dnf) sudo "$pkg_mgr" install -y openssl ;;
      pacman)  sudo pacman -S --noconfirm openssl ;;
    esac
    ok "OpenSSL installed."
  fi

  # Install curl
  if ! command -v curl &>/dev/null; then
    info "Installing curl..."
    case "$pkg_mgr" in
      brew)    brew install curl ;;
      apt)     sudo apt-get install -y curl ;;
      yum|dnf) sudo "$pkg_mgr" install -y curl ;;
      pacman)  sudo pacman -S --noconfirm curl ;;
    esac
    ok "curl installed."
  fi

  # Install python3
  if ! command -v python3 &>/dev/null; then
    info "Installing Python3..."
    case "$pkg_mgr" in
      brew)    brew install python3 ;;
      apt)     sudo apt-get install -y python3 ;;
      yum|dnf) sudo "$pkg_mgr" install -y python3 ;;
      pacman)  sudo pacman -S --noconfirm python ;;
    esac
    ok "Python3 installed."
  fi

  # Install jq
  if ! command -v jq &>/dev/null; then
    info "Installing jq..."
    case "$pkg_mgr" in
      brew)    brew install jq ;;
      apt)     sudo apt-get install -y jq ;;
      yum|dnf) sudo "$pkg_mgr" install -y jq ;;
      pacman)  sudo pacman -S --noconfirm jq ;;
    esac
    ok "jq installed."
  fi

  # Install Go
  local required_go
  required_go=$(required_go_version)
  local need_go=false

  if ! command -v go &>/dev/null; then
    need_go=true
  elif [ -n "$required_go" ]; then
    local current_go
    current_go=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
    if ! version_gte "$current_go" "$required_go"; then
      need_go=true
    fi
  fi

  if [ "$need_go" = "true" ] && [ -n "$required_go" ]; then
    info "Installing Go ${required_go}..."
    local go_archive="go${required_go}.${os}-${arch}.tar.gz"
    local go_url="https://go.dev/dl/${go_archive}"

    if [ "$os" = "darwin" ]; then
      # macOS: use the pkg installer for cleaner installation
      local go_pkg="go${required_go}.${os}-${arch}.pkg"
      local go_pkg_url="https://go.dev/dl/${go_pkg}"
      info "Downloading ${go_pkg_url}..."
      curl -fSL -o "/tmp/${go_pkg}" "$go_pkg_url"
      sudo installer -pkg "/tmp/${go_pkg}" -target /
      rm -f "/tmp/${go_pkg}"
    else
      # Linux: download and extract to /usr/local
      info "Downloading ${go_url}..."
      curl -fSL -o "/tmp/${go_archive}" "$go_url"
      sudo rm -rf /usr/local/go
      sudo tar -C /usr/local -xzf "/tmp/${go_archive}"
      rm -f "/tmp/${go_archive}"

      # Persist Go PATH for current user
      local shell_rc=""
      if [ -f "$HOME/.zshrc" ]; then
        shell_rc="$HOME/.zshrc"
      elif [ -f "$HOME/.bashrc" ]; then
        shell_rc="$HOME/.bashrc"
      elif [ -f "$HOME/.profile" ]; then
        shell_rc="$HOME/.profile"
      fi

      if [ -n "$shell_rc" ] && ! grep -q '/usr/local/go/bin' "$shell_rc" 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> "$shell_rc"
        info "Added Go to PATH in ${shell_rc}"
      fi
      export PATH=$PATH:/usr/local/go/bin
    fi

    # Verify
    if command -v go &>/dev/null; then
      local installed_ver
      installed_ver=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
      ok "Go ${installed_ver} installed."
    else
      error "Go installation completed but 'go' not found in PATH."
      warn "You may need to open a new terminal or add /usr/local/go/bin to PATH."
    fi
  elif [ "$need_go" = "true" ]; then
    warn "Go version not specified. Set GO_VERSION in .env or ensure go.mod exists."
  fi

  echo ""
  info "Running dependency check..."
  cmd_check_deps
}

cmd_init_dirs() {
  info "Creating directory structure..."
  mkdir -p config tls data logs backups
  chmod 700 config tls data

  # Check plugin binary
  local plugin_binary="${PLUGIN_NAME:-vault-plugin-crypto}-${PLUGIN_VERSION:-v0.2.0}"
  if [ ! -f "../build/${plugin_binary}" ]; then
    warn "Plugin binary not found: ../build/${plugin_binary}"
    warn "Run 'make build' in the project root first."
  else
    ok "Plugin binary found: ../build/${plugin_binary}"
  fi

  ok "Directories created: config/ tls/ data/ logs/ backups/"
}

cmd_gen_tls() {
  info "Generating self-signed TLS certificates..."
  warn "These certificates are for TESTING only. Use real certificates in production."

  local fqdn="${VAULT_FQDN:-localhost}"

  # Generate CA key and certificate
  openssl genrsa -out tls/ca-key.pem 4096 2>/dev/null
  openssl req -new -x509 -days 36500 -key tls/ca-key.pem \
    -out tls/ca.pem -subj "/CN=Vault CA" 2>/dev/null

  # Create SAN config (detect if fqdn is an IP address or hostname)
  local san_entries="DNS:localhost,IP:127.0.0.1"
  if echo "$fqdn" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    san_entries="IP:${fqdn},${san_entries}"
  elif [ "$fqdn" != "localhost" ]; then
    san_entries="DNS:${fqdn},${san_entries}"
  fi
  cat > tls/_openssl.cnf <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
[req_dn]
[v3_req]
subjectAltName = ${san_entries}
EOF

  # Generate server key, CSR, and certificate
  openssl genrsa -out tls/key.pem 4096 2>/dev/null
  openssl req -new -key tls/key.pem -out tls/_vault.csr \
    -subj "/CN=${fqdn}" 2>/dev/null
  openssl x509 -req -days 36500 -in tls/_vault.csr \
    -CA tls/ca.pem -CAkey tls/ca-key.pem -CAcreateserial \
    -out tls/cert.pem -extfile tls/_openssl.cnf -extensions v3_req 2>/dev/null

  # Cleanup temp files
  rm -f tls/_vault.csr tls/_openssl.cnf tls/ca.srl
  chmod 600 tls/*.pem

  ok "TLS certificates generated in tls/"
  info "  CA cert:     tls/ca.pem"
  info "  Server cert: tls/cert.pem (SAN: ${san_entries})"
  info "  Server key:  tls/key.pem"
}

cmd_prepare_config() {
  info "Generating Vault configuration..."

  local unseal="${UNSEAL_METHOD:-shamir}"
  local template="vault-${unseal}.hcl"
  local fqdn="${VAULT_FQDN:-localhost}"
  local scheme
  scheme="$(vault_scheme)"
  local tls_disable="${TLS_DISABLE:-false}"
  local log_level="${LOG_LEVEL:-info}"

  if [ ! -f "$template" ]; then
    error "Template not found: ${template}"
    error "UNSEAL_METHOD must be 'shamir' or 'awskms'"
    exit 1
  fi

  cp "$template" config/vault.hcl

  # Replace placeholders
  sed -i.bak "s|VAULT_API_ADDR_PLACEHOLDER|${scheme}://${fqdn}:${VAULT_PORT:-8200}|g" config/vault.hcl
  sed -i.bak "s|VAULT_CLUSTER_ADDR_PLACEHOLDER|${scheme}://${fqdn}:${VAULT_CLUSTER_PORT:-8201}|g" config/vault.hcl
  sed -i.bak "s|TLS_DISABLE_PLACEHOLDER|${tls_disable}|g" config/vault.hcl
  sed -i.bak "s|LOG_LEVEL_PLACEHOLDER|${log_level}|g" config/vault.hcl
  sed -i.bak "s|VAULT_NODE_ID_PLACEHOLDER|${VAULT_NODE_ID:-vault-1}|g" config/vault.hcl

  if [ "$unseal" = "awskms" ]; then
    sed -i.bak "s|AWS_REGION_PLACEHOLDER|${AWS_REGION:-us-east-1}|g" config/vault.hcl
    sed -i.bak "s|AWS_KMS_KEY_ID_PLACEHOLDER|${AWS_KMS_KEY_ID:-REPLACE_ME}|g" config/vault.hcl
  fi

  rm -f config/vault.hcl.bak
  chmod 600 config/vault.hcl

  ok "Configuration generated: config/vault.hcl (unseal: ${unseal})"
}

cmd_start() {
  info "Starting Vault container..."
  docker compose -f docker-compose.prod.yml --env-file .env up -d
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
    # Also accept 501 (not initialized) and 503 (sealed)
    local code
    code=$(curl_vault -o /dev/null -w "%{http_code}" "${addr}/v1/sys/health" 2>/dev/null || echo "000")
    if [ "$code" = "501" ] || [ "$code" = "503" ] || [ "$code" = "200" ] || [ "$code" = "429" ]; then
      ok "Vault is responding at ${addr} (HTTP ${code})"
      return
    fi
    info "Waiting... (${i}/10)"
    sleep 2
  done
  error "Vault did not become ready. Check logs: docker compose -f docker-compose.prod.yml logs"
  exit 1
}

cmd_stop() {
  info "Stopping Vault container..."
  docker compose -f docker-compose.prod.yml --env-file .env down
  ok "Vault container stopped"
}

cmd_vault_init() {
  local addr
  addr="$(vault_addr)"
  local unseal="${UNSEAL_METHOD:-shamir}"
  local shares="${KEY_SHARES:-5}"
  local threshold="${KEY_THRESHOLD:-3}"

  # Check if already initialized
  local init_status
  init_status=$(curl_vault "${addr}/v1/sys/health" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
  if [ "$init_status" = "200" ] || [ "$init_status" = "503" ] || [ "$init_status" = "429" ]; then
    warn "Vault is already initialized."
    return
  fi

  # Auto-unseal seals wrap the barrier key themselves, so /sys/init rejects
  # secret_shares/secret_threshold ("parameters ... not applicable to seal
  # type awskms"). What init splits into shares there is the RECOVERY key,
  # requested via recovery_shares/recovery_threshold instead.
  local payload
  if [ "$unseal" = "awskms" ]; then
    info "Initializing Vault with AWS KMS auto-unseal (recovery_shares=${shares}, recovery_threshold=${threshold})..."
    payload="{\"recovery_shares\":${shares},\"recovery_threshold\":${threshold}}"
  else
    info "Initializing Vault (shares=${shares}, threshold=${threshold})..."
    payload="{\"secret_shares\":${shares},\"secret_threshold\":${threshold}}"
  fi

  local result
  if ! result=$(curl_vault -S -X POST -d "$payload" "${addr}/v1/sys/init" 2>&1); then
    error "Cannot reach Vault at ${addr}: ${result}"
    exit 1
  fi

  # /sys/init reports failures (bad params, seal errors) in an "errors"
  # array with no root_token; never save an error body as the keys file.
  local api_err
  api_err=$(echo "$result" | python3 -c "import sys,json; print('; '.join(json.load(sys.stdin).get('errors') or []))" 2>/dev/null || echo "")
  if [ -n "$api_err" ]; then
    error "Vault initialization failed: ${api_err}"
    exit 1
  fi

  local root_token
  root_token=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('root_token',''))" 2>/dev/null || echo "")
  if [ -z "$root_token" ]; then
    error "Vault initialization failed (no root_token in response):"
    echo "$result" | python3 -m json.tool 2>/dev/null || echo "$result"
    exit 1
  fi

  echo "$result" > vault-init-keys.json
  chmod 600 vault-init-keys.json

  if [ "$unseal" = "awskms" ]; then
    ok "Vault initialized! Recovery keys saved to vault-init-keys.json"
    echo ""
    echo -e "${RED}===========================================================${NC}"
    echo -e "${RED}  CRITICAL: Securely store vault-init-keys.json NOW!${NC}"
    echo -e "${RED}  It contains the RECOVERY keys and root token.${NC}"
    echo -e "${RED}  Recovery keys do NOT unseal Vault (AWS KMS does), but${NC}"
    echo -e "${RED}  they are the only way to regenerate a lost root token.${NC}"
    echo -e "${RED}  Distribute them to different administrators.${NC}"
    echo -e "${RED}  Delete this file after securely backing up the keys.${NC}"
    echo -e "${RED}===========================================================${NC}"
  else
    ok "Vault initialized! Keys saved to vault-init-keys.json"
    echo ""
    echo -e "${RED}===========================================================${NC}"
    echo -e "${RED}  CRITICAL: Securely store vault-init-keys.json NOW!${NC}"
    echo -e "${RED}  It contains the unseal keys and root token.${NC}"
    echo -e "${RED}  Distribute unseal keys to different administrators.${NC}"
    echo -e "${RED}  Delete this file after securely backing up the keys.${NC}"
    echo -e "${RED}===========================================================${NC}"
  fi
  echo ""

  info "Root Token: ${root_token}"

  if [ "$unseal" = "awskms" ]; then
    echo ""
    echo -e "${YELLOW}Vault unsealed itself via AWS KMS during init -- no manual unseal needed.${NC}"
  fi
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
      warn "Container logs: docker compose -f docker-compose.prod.yml logs vault"
    fi
    return
  fi

  # Shamir unseal
  local threshold="${KEY_THRESHOLD:-3}"
  info "Shamir unseal: need ${threshold} key(s) to unseal"

  for i in $(seq 1 "$threshold"); do
    # Check if already unsealed
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
  local addr
  addr="$(vault_addr)"
  local plugin_name="${PLUGIN_NAME:-vault-plugin-crypto}"
  local plugin_version="${PLUGIN_VERSION:-v0.2.0}"
  local plugin_binary="${plugin_name}-${plugin_version}"
  local mount_path="${PLUGIN_MOUNT_PATH:-crypto}"

  # Get root token (from argument, file, or interactive prompt)
  local vault_token
  vault_token=$(read_root_token "${1:-}")

  # Calculate SHA256
  info "Calculating plugin SHA256..."
  local sha256
  sha256=$(shasum -a 256 "../build/${plugin_binary}" | cut -d ' ' -f1)
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
    if echo "$enable_result" | grep -q "existing mount at"; then
      warn "Plugin already mounted at /${mount_path}, reloading..."
      curl_vault -X PUT \
        -H "X-Vault-Token: ${vault_token}" \
        -d "{\"mounts\":[\"${mount_path}/\"]}" \
        "${addr}/v1/sys/plugins/reload/backend" > /dev/null 2>&1
      ok "Plugin reloaded"
    else
      error "Plugin enable failed:"
      echo "$enable_result" | python3 -m json.tool 2>/dev/null || echo "$enable_result"
      exit 1
    fi
  else
    ok "Plugin enabled at /${mount_path}"
  fi

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

cmd_enable_audit() {
  local addr
  addr="$(vault_addr)"

  local vault_token
  vault_token=$(read_root_token "${1:-}")

  info "Enabling file audit log..."
  local result
  result=$(curl_vault -X PUT \
    -H "X-Vault-Token: ${vault_token}" \
    -d '{"type":"file","options":{"file_path":"/vault/logs/audit.log"}}' \
    "${addr}/v1/sys/audit/file")

  # Empty response = success; check for errors
  if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'errors' in d else 1)" 2>/dev/null; then
    # Check if already enabled
    if echo "$result" | grep -q "already registered"; then
      warn "Audit log already enabled"
    else
      error "Failed to enable audit log:"
      echo "$result" | python3 -m json.tool 2>/dev/null || echo "$result"
      exit 1
    fi
  else
    ok "Audit log enabled at /vault/logs/audit.log"
  fi
}

# Create the least-privilege application token (policy: crypto-app).
# Replaces the old create-admin command, whose crypto-admin policy granted a
# blanket "${mount_path}/*" -- future plugin endpoints would have been granted
# automatically. Args: $1 = "--policy-only" or "", $2 = optional root token
# (used by cmd_all; never passed from the CLI to keep tokens out of `ps`).
cmd_gen_app_token() {
  local policy_only=false
  [ "${1:-}" = "--policy-only" ] && policy_only=true

  local addr
  addr="$(vault_addr)"
  local mount_path="${PLUGIN_MOUNT_PATH:-crypto}"
  local policy_name="crypto-app"
  local token_file="app.token"

  if [ "$policy_only" = true ]; then
    info "Rewriting policy '${policy_name}' only; no new token will be created."
  elif [ -f "$token_file" ]; then
    # Keeps `all` re-runnable without minting a new token every time.
    warn "${token_file} already exists, skipping token creation."
    info "To reissue:                rm ${token_file} && ./setup.sh gen-app-token"
    info "To refresh only the policy: ./setup.sh gen-app-token --policy-only"
    return
  else
    info "Generating a least-privilege application token via the Vault API (no vault CLI needed)..."
  fi

  local vault_token
  vault_token=$(read_root_token "${2:-}")

  # 1. Policy covering exactly the crypto plugin's API surface (the four
  #    paths registered in internal/backend/backend.go), nothing else.
  #    `+` matches a single path segment, which cannot be escaped: a valid
  #    external_id never contains `/`. LIST requests are ACL-checked with a
  #    trailing slash on the path, hence the separate "keys/" rule.
  #    lookup-self/renew-self are granted by the built-in `default` policy,
  #    which this token opts out of via no_default_policy, so they must be
  #    granted explicitly here.
  info "Writing policy '${policy_name}' (create/list/read keys + sign + tx build)..."
  local policy_hcl
  policy_hcl=$(cat <<EOF
path "${mount_path}/keys" {
  capabilities = ["create", "update"]
}
path "${mount_path}/keys/" {
  capabilities = ["list"]
}
path "${mount_path}/keys/+" {
  capabilities = ["read"]
}
path "${mount_path}/keys/+/sign" {
  capabilities = ["create", "update"]
}
path "${mount_path}/tx/build/evm" {
  capabilities = ["create", "update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOF
)
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

  # Policies are resolved by name on every request, so after a plugin upgrade
  # adds endpoints, rerunning with --policy-only is enough -- already-issued
  # app tokens pick up the new rules immediately.
  if [ "$policy_only" = true ]; then
    echo ""
    ok "Existing tokens bound to '${policy_name}' picked up the new rules immediately."
    info "Verify with: ./setup.sh token-status --app-token"
    return
  fi

  # 2. Create an orphan, periodic token bound to that policy, with no default
  #    policy. no_parent -> survives revocation of the root token used here;
  #    period -> renewable indefinitely, never hits a max TTL.
  info "Creating periodic app token (period=720h, orphan, no default policy)..."
  local create_payload
  create_payload='{"policies":["'"${policy_name}"'"],"period":"720h","no_parent":true,"no_default_policy":true,"display_name":"crypto-app","meta":{"purpose":"application-access-to-crypto-plugin"}}'
  local resp
  resp=$(curl_vault -X POST \
    -H "X-Vault-Token: ${vault_token}" \
    -d "$create_payload" \
    "${addr}/v1/auth/token/create" 2>/dev/null || echo "")

  local app_token
  app_token=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('auth',{}).get('client_token',''))" 2>/dev/null || echo "")
  if [ -z "$app_token" ]; then
    error "Token creation failed. Vault response:"
    echo "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"
    exit 1
  fi

  # 3. Persist with tight permissions, then display.
  ( umask 077; printf '%s' "$app_token" > "$token_file" )
  chmod 600 "$token_file"

  ok "App token created and saved to ${token_file} (mode 600)"
  echo ""
  info "Token: ${app_token}"
  echo ""
  echo -e "${YELLOW}Next steps:${NC}"
  echo "  - Hand the token to the application (env var / secret manager). It can"
  echo "    ONLY call the ${mount_path} plugin API: create/list/read keys, sign,"
  echo "    and tx/build/evm -- no other Vault paths."
  echo "  - Check its TTL:  ./setup.sh token-status --app-token"
  echo "  - Periodic token (720h): the app (most Vault SDKs do this) or a cron"
  echo "    must POST auth/token/renew-self before expiry."
  echo "  - Plugin upgrade added endpoints? ./setup.sh gen-app-token --policy-only"
  echo "  - Usage examples: see DEPLOY.md -> 应用 token"
}

# Show a token's TTL, policies and renewal health via lookup-self -- no root
# token needed, unlike the old token-info which looked tokens up with root.
cmd_token_status() {
  local addr
  addr="$(vault_addr)"

  # Token source: --app-token reads the saved app token, VAULT_TOKEN wins
  # over the prompt. Never accept a token as a positional argument: it would
  # be visible in `ps` output and land in shell history.
  local vault_token=""
  if [ "${1:-}" = "--app-token" ]; then
    local token_file="app.token"
    if [ ! -f "$token_file" ]; then
      error "App token not found: ${token_file}"
      error "Create one with: ./setup.sh gen-app-token"
      exit 1
    fi
    vault_token=$(cat "$token_file")
    info "Using app token from ${token_file}"
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
      error "     (b) applies to tokens issued before that rule existed, e.g. an"
      error "     old crypto-admin token from create-admin."
      error "     Fix for app tokens without reissuing: ./setup.sh gen-app-token --policy-only"
      exit 1
      ;;
    503)
      error "Vault is sealed (HTTP 503). Unseal first: ./setup.sh vault-unseal"
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
                    "Check the renewing cron/application logs.")
if expire is not None and not renewable:
    warnings.append("Token is NOT renewable; it will expire and cannot be extended.")

if warnings:
    print()
    for w in warnings:
        print(f"  [WARN] {w}")
'
  echo ""
}

cmd_status() {
  local addr
  addr="$(vault_addr)"

  echo -e "\n${YELLOW}=== Vault Status ===${NC}\n"

  # Container status
  info "Container:"
  local container="${VAULT_CONTAINER_NAME:-vault-crypto-prod}"
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
    200) ok "  Status: active (unsealed, initialized)" ;;
    429) warn "  Status: standby" ;;
    472) warn "  Status: disaster recovery secondary" ;;
    473) warn "  Status: performance standby" ;;
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
  info "  Sealed: ${sealed}"
  info "  Seal type: ${seal_type}"

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
    info "To restore: ./setup.sh restore ${backup_file}"
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
    error "Usage: ./setup.sh restore <snapshot-file>"
    error "Example: ./setup.sh restore backups/vault-backup-20250215_120000.snap"
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
    if [ "${UNSEAL_METHOD:-shamir}" = "awskms" ]; then
      info "Vault auto-unseals via AWS KMS after applying the snapshot."
    else
      warn "Vault will restart automatically. You may need to unseal again (Shamir mode)."
    fi
    info "Run: ./setup.sh status"
  else
    error "Restore failed (HTTP ${http_code}). Check your token permissions."
    error "Required policy: path \"sys/storage/raft/snapshot\" { capabilities = [\"create\", \"update\"] }"
    exit 1
  fi
}

cmd_all() {
  echo -e "${YELLOW}=== Full Deployment ===${NC}\n"
  load_env

  cmd_check_deps || { error "Please install missing dependencies first: ./setup.sh install-deps"; exit 1; }
  echo ""

  cmd_init_dirs
  echo ""

  if [ ! -f tls/cert.pem ] && [ "${TLS_DISABLE:-false}" != "true" ]; then
    cmd_gen_tls
    echo ""
  fi

  cmd_prepare_config
  echo ""

  cmd_start
  echo ""

  cmd_vault_init
  echo ""

  cmd_vault_unseal
  echo ""

  # Read root token from vault-init-keys.json for automated operations
  local root_token
  root_token=$(read_root_token)

  cmd_register_plugin "$root_token"
  echo ""

  cmd_enable_audit "$root_token"
  echo ""

  cmd_gen_app_token "" "$root_token"
  echo ""

  cmd_status
}

cmd_help() {
  echo "Vault Crypto Plugin - Deployment Helper"
  echo ""
  echo "Usage: $0 <command>"
  echo ""
  echo "Commands:"
  echo "  check-deps      Check required dependencies"
  echo "  install-deps    Install missing dependencies (Docker, Go, openssl, etc.)"
  echo "  init-dirs       Create required directory structure"
  echo "  gen-tls         Generate self-signed TLS certificates (testing only)"
  echo "  prepare-config  Generate vault.hcl from .env settings"
  echo "  start           Start Vault container"
  echo "  stop            Stop Vault container"
  echo "  vault-init      Initialize Vault (first time only)"
  echo "                  (shamir: creates unseal keys; awskms: creates recovery"
  echo "                   keys, Vault auto-unseals via KMS)"
  echo "  vault-unseal    Unseal Vault (Shamir; status check for awskms)"
  echo "  register-plugin Register and enable the crypto plugin"
  echo "  enable-audit    Enable file audit logging"
  echo "  gen-app-token   Create a least-privilege token for applications: crypto"
  echo "                  plugin API only (create/list/read keys, sign, tx build)"
  echo "                  (--policy-only rewrites the policy, e.g. after a plugin upgrade)"
  echo "  token-status    Show a token's TTL and policies (--app-token reads app.token)"
  echo "  status          Show Vault and plugin status"
  echo "  backup          Create a Raft snapshot backup (online, no downtime)"
  echo "  restore         Restore Vault from a Raft snapshot"
  echo "  all             Run full first-time deployment"
  echo "  help            Show this help message"
}

# ==================== Main ====================

COMMAND="${1:-help}"

# Load .env for most commands (except help and init-dirs)
case "$COMMAND" in
  help|check-deps|install-deps) ;;
  init-dirs)
    [ -f .env ] && load_env || true
    ;;
  all) ;; # all loads env itself
  *)
    load_env
    ;;
esac

case "$COMMAND" in
  check-deps)      cmd_check_deps ;;
  install-deps)    cmd_install_deps ;;
  init-dirs)       cmd_init_dirs ;;
  gen-tls)         cmd_gen_tls ;;
  prepare-config)  cmd_prepare_config ;;
  start)           cmd_start ;;
  stop)            cmd_stop ;;
  vault-init)      cmd_vault_init ;;
  vault-unseal)    cmd_vault_unseal ;;
  register-plugin) cmd_register_plugin ;;
  enable-audit)    cmd_enable_audit ;;
  gen-app-token)   cmd_gen_app_token "${2:-}" ;;
  create-admin)
    # Deprecated alias kept for muscle memory / old runbooks.
    warn "create-admin is deprecated; issuing a least-privilege 'crypto-app' token instead."
    cmd_gen_app_token "${2:-}"
    ;;
  token-status)    cmd_token_status "${2:-}" ;;
  token-info)
    # Deprecated alias for token-status.
    cmd_token_status "${2:-}"
    ;;
  status)          cmd_status ;;
  backup)          cmd_backup ;;
  restore)         cmd_restore "$@" ;;
  all)             cmd_all ;;
  help)            cmd_help ;;
  *)
    error "Unknown command: ${COMMAND}"
    cmd_help
    exit 1
    ;;
esac
