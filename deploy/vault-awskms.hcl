# Vault Production Configuration - AWS KMS Auto-Unseal
# Usage: copy to deploy/config/vault.hcl (done by setup.sh prepare-config)
#
# Required AWS IAM permissions: kms:Encrypt, kms:Decrypt, kms:DescribeKey
# AWS credentials via environment variables or IAM role (EC2 instance profile / ECS task role)

ui = true

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"

  # TLS - set tls_disable = true only behind a TLS-terminating reverse proxy
  tls_disable     = TLS_DISABLE_PLACEHOLDER
  tls_cert_file   = "/vault/tls/cert.pem"
  tls_key_file    = "/vault/tls/key.pem"
  tls_min_version = "tls12"
}

storage "raft" {
  path    = "/vault/data"
  node_id = "VAULT_NODE_ID_PLACEHOLDER"
}

plugin_directory = "/vault/plugins"

api_addr     = "VAULT_API_ADDR_PLACEHOLDER"
cluster_addr = "VAULT_CLUSTER_ADDR_PLACEHOLDER"

disable_mlock = false

log_level = "LOG_LEVEL_PLACEHOLDER"

# AWS KMS Auto-Unseal
seal "awskms" {
  region     = "AWS_REGION_PLACEHOLDER"
  kms_key_id = "AWS_KMS_KEY_ID_PLACEHOLDER"
}

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}

default_lease_ttl = "768h"
max_lease_ttl     = "8760h"
