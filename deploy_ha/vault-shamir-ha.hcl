# Vault HA Configuration - Shamir Unseal + Raft Storage (3-node cluster)
# Usage: copy to deploy_ha/config/vault.hcl (done by setup-ha.sh prepare-config)

ui = true

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"

  # TLS is REQUIRED for HA cluster communication
  tls_disable     = TLS_DISABLE_PLACEHOLDER
  tls_cert_file   = "/vault/config/tls/cert.pem"
  tls_key_file    = "/vault/config/tls/key.pem"
  tls_client_ca_file = "/vault/config/tls/ca.pem"
  tls_min_version = "tls12"
}

storage "raft" {
  path    = "/vault/data"
  node_id = "VAULT_NODE_ID_PLACEHOLDER"

  retry_join {
    leader_api_addr         = "VAULT_NODE_1_API_ADDR_PLACEHOLDER"
    leader_ca_cert_file     = "/vault/config/tls/ca.pem"
    leader_client_cert_file = "/vault/config/tls/cert.pem"
    leader_client_key_file  = "/vault/config/tls/key.pem"
  }

  retry_join {
    leader_api_addr         = "VAULT_NODE_2_API_ADDR_PLACEHOLDER"
    leader_ca_cert_file     = "/vault/config/tls/ca.pem"
    leader_client_cert_file = "/vault/config/tls/cert.pem"
    leader_client_key_file  = "/vault/config/tls/key.pem"
  }

  retry_join {
    leader_api_addr         = "VAULT_NODE_3_API_ADDR_PLACEHOLDER"
    leader_ca_cert_file     = "/vault/config/tls/ca.pem"
    leader_client_cert_file = "/vault/config/tls/cert.pem"
    leader_client_key_file  = "/vault/config/tls/key.pem"
  }
}

plugin_directory = "/vault/plugins"

api_addr     = "VAULT_API_ADDR_PLACEHOLDER"
cluster_addr = "VAULT_CLUSTER_ADDR_PLACEHOLDER"

disable_mlock = false

log_level = "LOG_LEVEL_PLACEHOLDER"

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}

default_lease_ttl = "768h"
max_lease_ttl     = "8760h"
