# Vault 加密钱包插件

用于区块链应用的 HashiCorp Vault Secrets Engine 插件。密钥在 Vault 内生成、存储和使用，私钥永不离开 Vault——应用只拿到公钥和签名结果。

**版本：** v0.2.0（取自 [internal/backend/backend.go](internal/backend/backend.go) 的 `Version` 常量，构建与插件注册均以它为准）

## 功能特性

- **多曲线支持**：secp256k1（EVM/BTC）、secp256r1（P-256）、ed25519（Solana）
- **安全密钥生成**：使用加密安全随机数生成密钥
- **私钥保护**：私钥永不离开 Vault，使用 SealWrap 加密存储
- **灵活签名**：支持 hex/base64 输入输出格式
- **交易构建**：内置 EVM 交易（legacy/EIP-1559）签名载荷构建
- **灵活标识**：支持 name 和 external_id 标识密钥，external_id 全局唯一
- **公钥获取**：API 返回公钥信息（私钥永不暴露）

## 构建插件

产物以版本号命名（`vault-plugin-crypto-vX.Y.Z`），发布新版本前先更新 `backend.go` 的 `Version` 常量：

```bash
make build       # linux/amd64（部署用）→ build/vault-plugin-crypto-v0.2.0，并生成 .sha256
make build-all   # 多平台交叉编译（-linux-amd64 / -linux-arm64 / -darwin-*）
make build-local # 当前平台（本地调试用）
```

构建后把二进制复制到对应部署目录的 `plugins/`：

```bash
cp build/vault-plugin-crypto-v0.2.0 deploy/plugins/      # 单机部署
cp build/vault-plugin-crypto-v0.2.0 deploy_ha/plugins/   # HA 3 节点部署
```

两个 `plugins/` 目录都被 git 跟踪：提交二进制后，部署机 `git pull` 即完成分发（HA 集群三台节点都要有同一份二进制）。

## 部署与升级

具体部署、运维、升级步骤不在本 README 展开，见各部署目录内的完整文档：

| 场景 | 文档 |
| --- | --- |
| 单机（Docker，Shamir / AWS KMS 解封） | [deploy/DEPLOY.md](deploy/DEPLOY.md) |
| HA 3 节点（Raft 集群，AWS 单 AZ，Shamir / AWS KMS 解封） | [deploy_ha/DEPLOY_HA.md](deploy_ha/DEPLOY_HA.md) |

两份文档均覆盖：部署流程、应用接入 token（`gen-app-token`，最小权限）、备份与恢复、灾难恢复、**插件升级与回滚**（[单机升级](deploy/DEPLOY.md#插件升级) / [HA 升级](deploy_ha/DEPLOY_HA.md#插件升级)）。

## API 参考

插件挂载在 `crypto/`（可配置），共 4 个端点：创建 key、列出/读取 key、签名、构建 EVM 交易。

### 创建密钥

```bash
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"curve":"secp256k1","name":"my-key","external_id":"user-123"}' \
  $VAULT_ADDR/v1/crypto/keys
```

**参数：**
- `curve`（必需）：`secp256k1`、`secp256r1` 或 `ed25519`
- `name`（必需）：密钥名称，可重复（仅允许字母、数字、空格、下划线、连字符、冒号）
- `external_id`（必需）：外部标识符（允许字母、数字、点、下划线、连字符、冒号；首尾必须为字母、数字或下划线）
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

### 构建 EVM 交易

生成交易的待签哈希（`signing_hash`），交给上面的签名端点使用：

```bash
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"tx_type":"eip1559","chain_id":1,"nonce":0,"gas_limit":21000,"to":"0x...","value":"1000000000000000","max_fee_per_gas":"30000000000","max_priority_fee_per_gas":"1000000000"}' \
  $VAULT_ADDR/v1/crypto/tx/build/evm
```

**参数：** `tx_type`（`legacy`/`eip1559`）、`chain_id`、`nonce`、`gas_limit` 必需；`to`、`value`、`data` 可选；legacy 用 `gas_price`，eip1559 用 `max_fee_per_gas` + `max_priority_fee_per_gas`。

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
- 所有操作都需要有效的 Vault 认证；应用接入使用最小权限 token（见部署文档的 `gen-app-token`）

## 开发

```bash
make dev        # 构建 + 拉起本地 Vault + 注册挂载插件，一条命令进入可用状态
make quicktest  # 冒烟：建一个 key 并列出
make test       # 单元测试
make fmt        # 代码格式化
make dev-clean  # 重置本地开发环境（清除数据）
./test.sh       # 集成测试脚本（注意：脚本内 VAULT_TOKEN 为硬编码，需按环境修改后使用）
```

## 许可证

MIT
