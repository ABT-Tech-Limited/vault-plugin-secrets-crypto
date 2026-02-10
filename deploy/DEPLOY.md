# Vault 加密钱包插件 - 生产部署指南

## 目录

- [前置条件](#前置条件)
- [架构概述](#架构概述)
- [目录结构](#目录结构)
- [快速部署](#快速部署)
- [TLS 证书准备](#tls-证书准备)
- [方案 A：Shamir 密钥解封](#方案-ashamir-密钥解封)
- [方案 B：AWS KMS 自动解封](#方案-baws-kms-自动解封)
- [Vault 初始化与解封](#vault-初始化与解封)
- [插件注册与启用](#插件注册与启用)
- [健康检查与验证](#健康检查与验证)
- [备份与恢复](#备份与恢复)
- [安全加固清单](#安全加固清单)
- [故障排查](#故障排查)
- [附录](#附录)

---

## 前置条件

| 依赖 | 最低版本 | 说明 |
|------|---------|------|
| Docker Engine | 20.10+ | 容器运行时 |
| Docker Compose | V2 | 使用 `docker compose` 命令 |
| openssl | - | TLS 证书生成 |
| curl | - | API 调用 |
| python3 | 3.6+ | JSON 解析（setup.sh 使用） |
| 磁盘空间 | 1GB+ | Vault 数据与日志存储 |

**可选依赖：**
- `jq` — JSON 格式化输出
- Vault CLI — 直接命令行操作
- AWS CLI — AWS KMS 密钥管理（方案 B）

---

## 架构概述

```
┌─────────────────────────────────────────────┐
│              Docker Host                     │
│                                              │
│  ┌─────────────────────────────────────┐    │
│  │         Vault Container              │    │
│  │                                      │    │
│  │  ┌──────────┐   ┌────────────────┐  │    │
│  │  │ Vault    │──▶│ crypto plugin  │  │    │
│  │  │ Server   │   │ (secrets engine)│  │    │
│  │  └──────────┘   └────────────────┘  │    │
│  │       │                              │    │
│  │       ▼                              │    │
│  │  ┌──────────┐                        │    │
│  │  │ File     │                        │    │
│  │  │ Storage  │                        │    │
│  │  └──────────┘                        │    │
│  └──────┬───────────────────────────────┘    │
│         │                                    │
│    Docker Volume (vault-data)                │
│                                              │
│  Ports: 8200 (API), 8201 (Cluster)          │
└─────────────────────────────────────────────┘
         │
         ▼
   TLS (HTTPS)
         │
   ┌─────┴─────┐
   │  Clients   │
   └───────────┘
```

**解封方式对比：**

| 特性 | Shamir 密钥 | AWS KMS |
|------|------------|---------|
| 外部依赖 | 无 | AWS 账户 |
| 重启后 | 需手动解封 | 自动解封 |
| 密钥管理 | 自行分发保管 | AWS 托管 |
| 适用场景 | 通用 | AWS 云环境 |
| 成本 | 免费 | KMS API 调用费用 |

---

## 目录结构

```
deploy/
├── docker-compose.prod.yml    # Docker Compose 生产配置
├── vault-shamir.hcl           # Vault 配置模板（Shamir 解封）
├── vault-awskms.hcl           # Vault 配置模板（AWS KMS 解封）
├── .env.example               # 环境变量模板
├── .env                       # 环境变量（从 .env.example 复制，不提交 Git）
├── setup.sh                   # 部署辅助脚本
├── DEPLOY.md                  # 本文档
├── config/                    # [自动生成] Vault 运行配置
│   └── vault.hcl
├── tls/                       # [自动生成/手动放置] TLS 证书
│   ├── ca.pem
│   ├── cert.pem
│   └── key.pem
├── logs/                      # [自动生成] 审计日志目录
└── vault-init-keys.json       # [自动生成] 初始化密钥（务必安全保管后删除）
```

> **注意：** `config/`、`tls/`、`logs/`、`.env`、`vault-init-keys.json` 已在 `.gitignore` 中排除。

---

## 快速部署

**Shamir 解封（最简方式）：**

```bash
# 1. 构建插件
make build

# 2. 进入 deploy 目录并配置
cd deploy
cp .env.example .env
# 编辑 .env，至少修改 VAULT_FQDN

# 3. 一键部署
./setup.sh all
```

**AWS KMS 解封：**

```bash
make build
cd deploy
cp .env.example .env
# 编辑 .env：
#   UNSEAL_METHOD=awskms
#   AWS_ACCESS_KEY_ID=xxx
#   AWS_SECRET_ACCESS_KEY=xxx
#   AWS_REGION=us-east-1
#   AWS_KMS_KEY_ID=xxx

./setup.sh all
```

以下章节为详细的分步说明。

---

## TLS 证书准备

### 测试环境：自签名证书

使用部署脚本自动生成：

```bash
./setup.sh gen-tls
```

生成的证书有效期 365 天，SAN 包含 `VAULT_FQDN`、`localhost`、`127.0.0.1`。

### 生产环境：正式证书

推荐使用 Let's Encrypt 或企业 CA 签发的证书，将以下文件放置到 `tls/` 目录：

| 文件 | 说明 |
|------|------|
| `cert.pem` | 服务器证书（包含完整证书链） |
| `key.pem` | 服务器私钥 |
| `ca.pem` | CA 根证书（可选，用于客户端验证） |

```bash
# 设置文件权限
chmod 600 tls/*.pem
```

### 禁用 TLS（反向代理场景）

如果 Vault 运行在 Nginx/Traefik 等反向代理之后，由代理终止 TLS：

```bash
# .env
TLS_DISABLE=true
```

---

## 方案 A：Shamir 密钥解封

Shamir 密钥分割是 Vault 的默认解封方式。初始化时生成 N 个密钥份额，需要 M 个份额（阈值）才能解封。

### 配置步骤

1. 编辑 `.env`：

```bash
UNSEAL_METHOD=shamir
KEY_SHARES=5      # 密钥总份额数
KEY_THRESHOLD=3   # 解封所需最少份额数
```

2. 生成配置：

```bash
./setup.sh prepare-config
```

### 密钥管理最佳实践

- **分散保管**：将 5 个密钥份额分发给 5 位不同的管理员
- **异地存储**：密钥份额存放在不同的物理位置
- **安全介质**：使用加密的 USB 设备或密码管理器存储
- **定期审查**：定期确认密钥持有者和可用性
- **不要**将所有密钥存放在同一个地方

---

## 方案 B：AWS KMS 自动解封

AWS KMS 自动解封使用 AWS Key Management Service 加密 Vault 的主密钥。Vault 重启后可自动解封，无需人工干预。

### 1. 创建 AWS KMS 密钥

```bash
aws kms create-key \
  --description "Vault auto-unseal key" \
  --key-usage ENCRYPT_DECRYPT \
  --origin AWS_KMS

# 记录返回的 KeyId
```

### 2. 配置 IAM 策略

创建最小权限的 IAM 策略：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"
    }
  ]
}
```

### 3. 配置环境变量

编辑 `.env`：

```bash
UNSEAL_METHOD=awskms
AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxxxxxx
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_REGION=us-east-1
AWS_KMS_KEY_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

> **提示：** 如果 Vault 运行在 EC2 实例上，可以使用 IAM 实例配置文件（Instance Profile），无需配置 `AWS_ACCESS_KEY_ID` 和 `AWS_SECRET_ACCESS_KEY`。

### 4. 生成配置并启动

```bash
./setup.sh prepare-config
./setup.sh start
```

---

## Vault 初始化与解封

### 首次初始化

```bash
./setup.sh vault-init
```

或手动执行：

```bash
VAULT_ADDR="https://127.0.0.1:8200"

# Shamir 方式
curl -s --cacert tls/ca.pem -X POST \
  -d '{"secret_shares":5,"secret_threshold":3}' \
  ${VAULT_ADDR}/v1/sys/init | python3 -m json.tool
```

初始化输出包含：
- **Unseal Keys**（Shamir 方式）或 **Recovery Keys**（AWS KMS 方式）
- **Root Token**

> **安全警告：** 立即安全保存这些信息！Root Token 和 Unseal Keys 只在初始化时输出一次。

### 解封

**Shamir 方式：**

```bash
./setup.sh vault-unseal
# 交互式输入 3 个（阈值）Unseal Key
```

或手动输入每个 key：

```bash
curl -s --cacert tls/ca.pem -X POST \
  -d '{"key":"UNSEAL_KEY_1"}' \
  ${VAULT_ADDR}/v1/sys/unseal

# 重复输入直到达到阈值
```

**AWS KMS 方式：**

无需手动操作，Vault 启动时自动连接 AWS KMS 解封。验证：

```bash
./setup.sh status
```

---

## 插件注册与启用

### 使用部署脚本

```bash
./setup.sh register-plugin
# 输入 Root Token
```

### 手动操作（API 方式）

```bash
VAULT_ADDR="https://127.0.0.1:8200"
VAULT_TOKEN="your-root-token"
PLUGIN_VERSION="v0.1.0"
PLUGIN_BINARY="vault-plugin-crypto-${PLUGIN_VERSION}"

# 1. 计算 SHA256
SHA256=$(shasum -a 256 ../build/${PLUGIN_BINARY} | cut -d ' ' -f1)

# 2. 注册插件
curl -s --cacert tls/ca.pem -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -d "{\"sha256\":\"${SHA256}\",\"command\":\"${PLUGIN_BINARY}\",\"version\":\"${PLUGIN_VERSION}\"}" \
  ${VAULT_ADDR}/v1/sys/plugins/catalog/secret/vault-plugin-crypto

# 3. 启用插件
curl -s --cacert tls/ca.pem -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -d "{\"type\":\"vault-plugin-crypto\",\"plugin_version\":\"${PLUGIN_VERSION}\",\"description\":\"Cryptographic key management for blockchain applications\"}" \
  ${VAULT_ADDR}/v1/sys/mounts/crypto

# 4. 验证
curl -s --cacert tls/ca.pem -X GET \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  ${VAULT_ADDR}/v1/sys/mounts/crypto/tune | python3 -m json.tool
```

### 手动操作（CLI 方式）

```bash
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="tls/ca.pem"
vault login  # 输入 Root Token

# 注册
SHA256=$(shasum -a 256 ../build/vault-plugin-crypto-v0.1.0 | cut -d ' ' -f1)
vault plugin register -sha256=${SHA256} -version=v0.1.0 secret vault-plugin-crypto

# 启用
vault secrets enable -path=crypto -plugin-name=vault-plugin-crypto plugin

# 验证
vault secrets list -detailed
```

---

## 健康检查与验证

### Vault 状态

```bash
# 部署脚本
./setup.sh status

# API
curl -s --cacert tls/ca.pem https://127.0.0.1:8200/v1/sys/health | python3 -m json.tool

# CLI
vault status
```

**健康检查返回码：**

| HTTP 状态码 | 含义 |
|------------|------|
| 200 | 正常（已初始化、已解封、Active） |
| 429 | Standby 节点 |
| 501 | 未初始化 |
| 503 | 已密封 |

### 功能测试

```bash
VAULT_ADDR="https://127.0.0.1:8200"
VAULT_TOKEN="your-token"

# 创建 secp256k1 密钥
curl -s --cacert tls/ca.pem -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -d '{"curve":"secp256k1","name":"test-prod-key"}' \
  ${VAULT_ADDR}/v1/crypto/keys | python3 -m json.tool

# 列出密钥
curl -s --cacert tls/ca.pem -X LIST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  ${VAULT_ADDR}/v1/crypto/keys | python3 -m json.tool
```

---

## 备份与恢复

### 备份策略

Vault 数据存储在 Docker Named Volume 中。建议每日备份。

**方法 1：停机备份（推荐）**

```bash
# 停止 Vault
./setup.sh stop

# 备份 volume
docker run --rm \
  -v vault-crypto-data:/data:ro \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/vault-backup-$(date +%Y%m%d).tar.gz -C /data .

# 重启 Vault
./setup.sh start
./setup.sh vault-unseal  # Shamir 方式需要重新解封
```

**方法 2：在线备份**

```bash
# 直接从 volume 复制（Vault 运行中，可能存在数据不一致风险）
docker run --rm \
  -v vault-crypto-data:/data:ro \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/vault-backup-$(date +%Y%m%d).tar.gz -C /data .
```

### 恢复

```bash
# 停止 Vault
./setup.sh stop

# 清空现有数据
docker volume rm vault-crypto-data
docker volume create vault-crypto-data

# 恢复数据
docker run --rm \
  -v vault-crypto-data:/data \
  -v $(pwd)/backups:/backup:ro \
  alpine tar xzf /backup/vault-backup-YYYYMMDD.tar.gz -C /data

# 重启
./setup.sh start
./setup.sh vault-unseal  # Shamir 方式
```

### 备份建议

- 每日自动备份（cron job）
- 备份文件加密存储
- 定期测试恢复流程
- 保留最近 30 天的备份
- **Unseal Keys 和 Root Token 单独备份，不与数据备份放在一起**

---

## 安全加固清单

- [ ] 启用 TLS（禁止生产环境使用 HTTP）
- [ ] 使用 TLS 1.2+，禁用弱密码套件
- [ ] 初始化完成后撤销 Root Token：`vault token revoke <root-token>`
- [ ] 配置 Vault 策略（最小权限），参考[附录](#vault-策略示例)
- [ ] 启用审计日志：`vault audit enable file file_path=/vault/logs/audit.log`
- [ ] 限制网络访问（防火墙仅允许必要端口和 IP）
- [ ] 定期轮换 TLS 证书
- [ ] Unseal Keys 分散保管（不同人、不同地点）
- [ ] 定期备份 Vault 数据
- [ ] Docker Socket 权限控制（限制可访问 Docker 的用户）
- [ ] 文件权限审查：配置文件 600，目录 700
- [ ] 监控 Vault 状态（Prometheus + Grafana）
- [ ] 设置日志告警（Vault 密封事件、认证失败等）

---

## 故障排查

### Vault 无法启动

```bash
# 查看容器日志
docker compose -f docker-compose.prod.yml logs vault

# 常见原因：
# - 配置文件语法错误 → 检查 config/vault.hcl
# - TLS 证书路径错误 → 检查 tls/ 目录下文件是否存在
# - 端口被占用 → netstat -tlnp | grep 8200
# - 权限问题 → 检查目录和文件权限
```

### 插件注册失败

```bash
# SHA256 不匹配
shasum -a 256 ../build/vault-plugin-crypto-v0.1.0
# 确保与注册时使用的值一致

# 二进制架构不匹配（必须是 linux/amd64）
file ../build/vault-plugin-crypto-v0.1.0
# 应显示：ELF 64-bit LSB executable, x86-64

# 权限问题
ls -la ../build/vault-plugin-crypto-v0.1.0
# 确保文件可执行
```

### TLS 错误

```bash
# 证书过期
openssl x509 -in tls/cert.pem -noout -dates

# SAN 不匹配
openssl x509 -in tls/cert.pem -noout -text | grep -A1 "Subject Alternative Name"

# 跳过 TLS 验证（临时调试）
curl -k https://127.0.0.1:8200/v1/sys/health
```

### Vault 密封状态恢复

**Shamir 方式：** Vault 重启后需要重新输入 Unseal Keys。

```bash
./setup.sh vault-unseal
```

**AWS KMS 方式：** 检查 AWS 连接和凭证。

```bash
# 检查 AWS 凭证
docker compose -f docker-compose.prod.yml exec vault env | grep AWS

# 检查 KMS 连接
docker compose -f docker-compose.prod.yml logs vault | grep -i kms
```

### 常见错误码

| 错误 | 可能原因 | 解决方案 |
|------|---------|---------|
| `permission denied` | 文件权限问题 | `chmod 600` 配置/证书文件 |
| `plugin not found` | 插件未注册或 SHA256 不匹配 | 重新注册插件 |
| `connection refused` | Vault 未运行 | `./setup.sh start` |
| `certificate signed by unknown authority` | CA 不受信任 | 使用 `--cacert` 或 `-k` |
| `server is not yet initialized` | Vault 未初始化 | `./setup.sh vault-init` |
| `Vault is sealed` | Vault 需要解封 | `./setup.sh vault-unseal` |

---

## 附录

### Vault 策略示例

**只读策略（crypto-readonly）：**

```hcl
# 允许列出和读取密钥信息
path "crypto/keys" {
  capabilities = ["list"]
}
path "crypto/keys/*" {
  capabilities = ["read"]
}
```

**签名者策略（crypto-signer）：**

```hcl
path "crypto/keys" {
  capabilities = ["list"]
}
path "crypto/keys/*" {
  capabilities = ["read"]
}
path "crypto/keys/+/sign" {
  capabilities = ["create", "update"]
}
```

**管理员策略（crypto-admin）：**

```hcl
path "crypto/*" {
  capabilities = ["create", "read", "update", "list"]
}
```

应用策略：

```bash
# 创建策略
vault policy write crypto-signer - <<EOF
path "crypto/keys" { capabilities = ["list"] }
path "crypto/keys/*" { capabilities = ["read"] }
path "crypto/keys/+/sign" { capabilities = ["create", "update"] }
EOF

# 创建 Token
vault token create -policy=crypto-signer -ttl=24h
```

### 启用审计日志

```bash
vault audit enable file file_path=/vault/logs/audit.log
vault audit list
```

### Prometheus 监控

Vault 内置 Prometheus 指标端点（已在 HCL 中配置 telemetry）：

```
https://VAULT_FQDN:8200/v1/sys/metrics?format=prometheus
```

Prometheus 配置示例：

```yaml
scrape_configs:
  - job_name: 'vault'
    scheme: https
    tls_config:
      ca_file: /path/to/ca.pem
    bearer_token: 'your-vault-token'
    metrics_path: '/v1/sys/metrics'
    params:
      format: ['prometheus']
    static_configs:
      - targets: ['vault.example.com:8200']
```

### Nginx 反向代理配置

```nginx
upstream vault {
    server 127.0.0.1:8200;
}

server {
    listen 443 ssl;
    server_name vault.example.com;

    ssl_certificate     /etc/ssl/certs/vault.pem;
    ssl_certificate_key /etc/ssl/private/vault-key.pem;

    location / {
        proxy_pass http://vault;  # Vault 内部可禁用 TLS
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

使用 Nginx 反代时，在 `.env` 中设置 `TLS_DISABLE=true`。

### 日常运维命令

```bash
# 启动
cd deploy && ./setup.sh start

# 停止
cd deploy && ./setup.sh stop

# 查看状态
cd deploy && ./setup.sh status

# 查看日志
docker compose -f deploy/docker-compose.prod.yml logs -f

# 从项目根目录使用 Makefile
make deploy-start
make deploy-stop
make deploy-logs
make deploy-status
```
