# Vault 加密钱包插件

用于区块链应用的 HashiCorp Vault Secrets Engine 插件，提供加密密钥管理功能。

**版本：** v0.1.0

## 功能特性

- **多曲线支持**：secp256k1（EVM/BTC）、secp256r1（P-256）、ed25519（Solana）
- **安全密钥生成**：使用加密安全随机数生成密钥
- **私钥保护**：私钥永不离开 Vault，使用 SealWrap 加密存储
- **灵活签名**：支持 hex/base64 输入输出格式
- **唯一标识**：支持通过 name 或 external_id 识别密钥
- **公钥获取**：API 返回公钥信息（私钥永不暴露）

## 快速开始

### 构建

```bash
# 构建插件（Linux/Docker 版本）
make build

# 构建所有平台版本
make build-all
```

### Docker 测试

```bash
# 1. 构建 Linux 版本插件
make build

# 2. 启动 Docker 中的 Vault
docker-compose up -d

# 3. 运行测试脚本
./test.sh

# 4. 停止 Vault
docker-compose down
```

## 生产环境部署（Docker）

### 前置条件

- Docker 和 Docker Compose
- Vault Enterprise 或 OSS 1.12+
- 为 `linux/amd64` 构建的插件二进制文件

### 第一步：准备 Docker 环境

创建生产环境 `docker-compose.yml`：

```yaml
version: '3.8'

services:
  vault:
    image: hashicorp/vault:1.21
    container_name: vault-prod
    restart: unless-stopped
    ports:
      - "8200:8200"
    environment:
      VAULT_ADDR: "http://127.0.0.1:8200"
    volumes:
      # 插件目录（只读以提高安全性）
      - ./plugins:/vault/plugins:ro
      # 持久化数据存储
      - vault-data:/vault/data
      # 配置文件
      - ./config:/vault/config:ro
    cap_add:
      - IPC_LOCK
    command: vault server -config=/vault/config/vault.hcl

volumes:
  vault-data:
```

### 第二步：Vault 配置

创建 `config/vault.hcl`：

```hcl
ui = true

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = false
  tls_cert_file = "/vault/config/tls/cert.pem"
  tls_key_file  = "/vault/config/tls/key.pem"
}

storage "file" {
  path = "/vault/data"
}

# 插件目录配置
plugin_directory = "/vault/plugins"

api_addr = "https://vault.example.com:8200"
cluster_addr = "https://vault.example.com:8201"
```

### 第三步：部署插件

```bash
# 1. 构建插件
make build

# 2. 复制插件到 plugins 目录
cp build/vault-plugin-crypto ./plugins/

# 3. 计算 SHA256 校验和
SHA256=$(shasum -a 256 ./plugins/vault-plugin-crypto | cut -d ' ' -f1)
echo "插件 SHA256: $SHA256"

# 4. 启动 Vault
docker-compose up -d

# 5. 初始化 Vault（仅首次）
docker exec -it vault-prod vault operator init

# 6. 解封 Vault（使用 5 个解封密钥中的 3 个）
docker exec -it vault-prod vault operator unseal <key1>
docker exec -it vault-prod vault operator unseal <key2>
docker exec -it vault-prod vault operator unseal <key3>
```

### 第四步：注册并启用插件

```bash
# 设置环境变量
export VAULT_ADDR='https://vault.example.com:8200'
export VAULT_TOKEN='<your-root-token>'

# 注册插件（带版本号）
vault plugin register \
  -sha256=$SHA256 \
  -command=vault-plugin-crypto \
  -version=v0.1.0 \
  secret vault-plugin-crypto

# 启用插件（带描述）
vault secrets enable \
  -path=crypto \
  -plugin-name=vault-plugin-crypto \
  -plugin-version=v0.1.0 \
  -description="区块链应用加密密钥管理" \
  plugin

# 验证安装
vault secrets list -detailed | grep crypto
```

### 使用 API 注册

```bash
# 注册插件
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d "{\"sha256\":\"$SHA256\",\"command\":\"vault-plugin-crypto\",\"version\":\"v0.1.0\"}" \
  $VAULT_ADDR/v1/sys/plugins/catalog/secret/vault-plugin-crypto

# 启用插件
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"type":"vault-plugin-crypto","plugin_version":"v0.1.0","description":"区块链应用加密密钥管理"}' \
  $VAULT_ADDR/v1/sys/mounts/crypto
```

## 插件升级

### 方式一：滚动升级（推荐）

此方式可在不中断服务的情况下升级。

```bash
# 1. 构建新版本
make build

# 2. 计算新的 SHA256
NEW_SHA256=$(shasum -a 256 build/vault-plugin-crypto | cut -d ' ' -f1)
echo "新 SHA256: $NEW_SHA256"

# 3. 复制新插件到容器（临时使用不同名称）
cp build/vault-plugin-crypto ./plugins/vault-plugin-crypto-v0.2.0

# 4. 注册新版本（旧版本继续运行）
vault plugin register \
  -sha256=$NEW_SHA256 \
  -command=vault-plugin-crypto-v0.2.0 \
  -version=v0.2.0 \
  secret vault-plugin-crypto

# 5. 升级已挂载的插件到新版本
vault secrets tune \
  -plugin-version=v0.2.0 \
  crypto/

# 6. 重新加载插件以应用更改
vault plugin reload -plugin=vault-plugin-crypto

# 7. 验证升级
vault secrets list -detailed | grep crypto

# 8. 清理旧插件（验证后可选）
rm ./plugins/vault-plugin-crypto-v0.1.0
```

### 方式二：原地升级（需要重启）

适用于可接受短暂停机的简单部署。

```bash
# 1. 构建新版本
make build

# 2. 停止 Vault 容器
docker-compose stop vault

# 3. 替换插件二进制文件
cp build/vault-plugin-crypto ./plugins/vault-plugin-crypto

# 4. 计算新的 SHA256
NEW_SHA256=$(shasum -a 256 ./plugins/vault-plugin-crypto | cut -d ' ' -f1)

# 5. 启动 Vault 容器
docker-compose start vault

# 6. 解封 Vault
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# 7. 使用新 SHA256 重新注册插件
vault plugin register \
  -sha256=$NEW_SHA256 \
  -command=vault-plugin-crypto \
  -version=v0.2.0 \
  secret vault-plugin-crypto

# 8. 更新挂载到新版本
vault secrets tune \
  -plugin-version=v0.2.0 \
  crypto/

# 9. 重新加载插件
vault plugin reload -plugin=vault-plugin-crypto
```

### 方式三：API 升级

```bash
# 1. 注册新插件版本
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d "{\"sha256\":\"$NEW_SHA256\",\"command\":\"vault-plugin-crypto\",\"version\":\"v0.2.0\"}" \
  $VAULT_ADDR/v1/sys/plugins/catalog/secret/vault-plugin-crypto

# 2. 更新挂载配置
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"plugin_version":"v0.2.0"}' \
  $VAULT_ADDR/v1/sys/mounts/crypto/tune

# 3. 重新加载插件
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"plugin":"vault-plugin-crypto"}' \
  $VAULT_ADDR/v1/sys/plugins/reload/backend
```

### 验证升级

```bash
# 检查当前插件版本
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/sys/mounts/crypto/tune | jq '.data.plugin_version'

# 检查运行中的版本
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/sys/mounts | jq '."crypto/".running_plugin_version'

# 测试功能
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"curve":"secp256k1","name":"upgrade-test"}' \
  $VAULT_ADDR/v1/crypto/keys
```

### 回滚

如果升级后出现问题：

```bash
# 回滚到之前的版本
vault secrets tune \
  -plugin-version=v0.1.0 \
  crypto/

vault plugin reload -plugin=vault-plugin-crypto
```

## API 参考

### 创建密钥

```bash
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"curve":"secp256k1","name":"my-key","external_id":"user-123"}' \
  $VAULT_ADDR/v1/crypto/keys
```

**参数：**
- `curve`（必需）：`secp256k1`、`secp256r1` 或 `ed25519`
- `name`（必需）：密钥的唯一名称（仅允许字母、数字、下划线、连字符）
- `external_id`（必需）：外部标识符（仅允许字母、数字、点、下划线、连字符）
- `metadata`（可选）：键值对元数据（最多 16 个键）

**响应：**
```json
{
  "data": {
    "name": "my-key",
    "external_id": "user-123",
    "curve": "secp256k1",
    "public_key": "0x04a1b2c3...",
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

### 列出密钥

```bash
curl -X LIST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/crypto/keys
```

### 获取密钥信息

```bash
curl -X GET \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/crypto/keys/<external_id>
```

**响应包含：**
- `name`：用户提供的名称
- `external_id`：外部标识符
- `curve`：椭圆曲线类型
- `public_key`：十六进制编码的公钥（0x 前缀）
- `created_at`：创建时间戳

### 签名数据

```bash
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"data":"0x44fd2527dcebf3756a9cd61cf0b5313cb34e2d4de079810ed310b078e4616727","encoding":"hex","prehashed":true}' \
  $VAULT_ADDR/v1/crypto/keys/<external_id>/sign
```

**参数：**
- `data`（必需）：要签名的数据（十六进制或 base64 编码）
- `encoding`（可选）：输入编码，`hex`（默认）或 `base64`
- `output_format`（可选）：输出格式，`hex`（默认）、`base64` 或 `raw`
- `prehashed`（可选）：如果为 true，数据已经过哈希处理（默认：true）

**响应：**
```json
{
  "data": {
    "signature": "0x496c74441f3830feff4ef24df5a7ea5f100e1741e5bac85c206e1e0f51914d472815b8036e8ebfac06d88763deb3d68db214c46aa7cd12c8ebeaad109f98f9ed01",
    "curve": "secp256k1",
    "external_id": "user-123"
  }
}
```

## 签名格式

| 曲线 | 格式 | 长度 | 应用场景 |
|------|------|------|----------|
| secp256k1 | R \|\| S \|\| V | 65 字节 | Ethereum、EVM 链、Bitcoin |
| secp256r1 | R \|\| S | 64 字节 | 通用 ECDSA（P-256） |
| ed25519 | 签名 | 64 字节 | Solana、Sui、Aptos |

## 公钥格式

| 曲线 | 格式 | 长度 |
|------|------|------|
| secp256k1 | 0x04 \|\| X \|\| Y（非压缩） | 65 字节 |
| secp256r1 | 0x04 \|\| X \|\| Y（非压缩） | 65 字节 |
| ed25519 | 原始公钥 | 32 字节 |

## 安全性

- 私钥**永不**在任何 API 响应中返回
- 密钥使用 Vault 存储加密进行静态加密
- SealWrap 为密钥材料提供额外的加密层
- 签名操作后清除内存
- **密钥不可删除**，以确保安全性和审计合规性
- 所有操作都需要有效的 Vault 认证

## Vault 策略示例

### 只读策略（查看者）

```hcl
# 仅列出和查看密钥
path "crypto/keys" {
  capabilities = ["list"]
}

path "crypto/keys/*" {
  capabilities = ["read"]
}
```

### 签名者策略（应用程序）

```hcl
# 使用现有密钥签名
path "crypto/keys/*/sign" {
  capabilities = ["create", "update"]
}

# 读取密钥信息（获取公钥）
path "crypto/keys/*" {
  capabilities = ["read"]
}
```

### 管理员策略（密钥管理者）

```hcl
# 完整密钥管理
path "crypto/keys" {
  capabilities = ["create", "list"]
}

path "crypto/keys/*" {
  capabilities = ["read"]
}

path "crypto/keys/*/sign" {
  capabilities = ["create", "update"]
}
```

## 故障排除

### 插件注册失败

```bash
# 检查插件是否存在且可执行
ls -la /vault/plugins/vault-plugin-crypto

# 验证 SHA256 是否匹配
shasum -a 256 /vault/plugins/vault-plugin-crypto

# 检查 Vault 日志
docker logs vault-prod 2>&1 | grep -i plugin
```

### 版本不匹配错误

```
plugin version mismatch: vault-plugin-crypto reported version (v0.2.0) did not match requested version (v0.1.0)
```

**解决方案：** 使用与插件二进制文件匹配的正确版本进行注册。

### 升级后校验和不匹配

```
checksums did not match
```

**解决方案：** 重新计算 SHA256 并重新注册插件。

```bash
SHA256=$(shasum -a 256 ./plugins/vault-plugin-crypto | cut -d ' ' -f1)
vault plugin register -sha256=$SHA256 ...
```

### 在目录中找不到插件

```bash
# 列出所有已注册的插件
vault plugin list secret

# 检查特定插件
vault plugin info secret vault-plugin-crypto
```

## 开发

### 本地测试

```bash
# 以开发模式启动 Vault 并加载插件
make dev

# 在另一个终端
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# 启用插件
vault secrets enable -path=crypto -plugin-name=vault-plugin-crypto plugin
```

### 运行单元测试

```bash
make test
```

### 代码格式化

```bash
make fmt
```

## 许可证

MIT
