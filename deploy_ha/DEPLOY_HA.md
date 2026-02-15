# Vault 加密钱包插件 - HA 集群部署指南（3 节点）

## 目录

- [前置条件](#前置条件)
- [架构概述](#架构概述)
- [目录结构](#目录结构)
- [部署流程](#部署流程)
  - [第一步：准备（所有节点）](#第一步准备所有节点)
  - [第二步：生成 CA 证书（节点 1）](#第二步生成-ca-证书节点-1)
  - [第三步：分发 CA 并生成节点证书（所有节点）](#第三步分发-ca-并生成节点证书所有节点)
  - [第四步：配置并启动（所有节点）](#第四步配置并启动所有节点)
  - [第五步：初始化集群（节点 1）](#第五步初始化集群节点-1)
  - [第六步：解封（所有节点）](#第六步解封所有节点)
  - [第七步：注册插件（Leader 节点）](#第七步注册插件leader-节点)
  - [第八步：验证集群（任意节点）](#第八步验证集群任意节点)
- [备份与恢复](#备份与恢复)
- [日常运维](#日常运维)
- [故障转移](#故障转移)
- [安全加固清单](#安全加固清单)

---

## 前置条件

| 依赖 | 要求 | 说明 |
|------|------|------|
| 服务器 | 3 台 | 独立物理机或 VM |
| Docker Engine | 20.10+ | 每台服务器 |
| Docker Compose | V2 | 每台服务器 |
| openssl | - | TLS 证书生成 |
| curl | - | API 调用 |
| python3 | 3.6+ | JSON 解析 |
| 网络 | 互通 | 端口 8200 (API) + 8201 (Raft) |

**网络要求：**
- 3 台服务器之间 TCP 8200 和 8201 端口双向可达
- 建议使用内网 IP 或专用网络
- 防火墙需开放上述端口

---

## 架构概述

```
                    ┌─── Client Requests ───┐
                    ▼                       ▼
Server 1 (vault-1)        Server 2 (vault-2)        Server 3 (vault-3)
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Docker           │    │  Docker           │    │  Docker           │
│  ┌──────────────┐ │    │  ┌──────────────┐ │    │  ┌──────────────┐ │
│  │ Vault        │ │    │  │ Vault        │ │    │  │ Vault        │ │
│  │ + crypto     │ │    │  │ + crypto     │ │    │  │ + crypto     │ │
│  │   plugin     │ │    │  │   plugin     │ │    │  │   plugin     │ │
│  │              │ │    │  │              │ │    │  │              │ │
│  │ Raft Storage │ │    │  │ Raft Storage │ │    │  │ Raft Storage │ │
│  └──────┬───────┘ │    │  └──────┬───────┘ │    │  └──────┬───────┘ │
│         │  :8200  │    │         │  :8200  │    │         │  :8200  │
│         │  :8201  │    │         │  :8201  │    │         │  :8201  │
└─────────┼─────────┘    └─────────┼─────────┘    └─────────┼─────────┘
          │                        │                        │
          └──── Raft Consensus (TLS mutual auth) ───────────┘
```

**关键概念：**

| 概念 | 说明 |
|------|------|
| Leader | 处理所有写请求，通过 Raft 复制到 Follower |
| Follower | 接收读请求（需 Token），写请求自动转发到 Leader |
| Quorum | 3 节点集群中需要 2 个节点存活才能运作 |
| retry_join | 节点启动后自动发现并加入集群 |

---

## 目录结构

每台服务器上的文件结构：

```
deploy_ha/
├── docker-compose.ha.yml     # Docker Compose 配置
├── vault-shamir-ha.hcl       # Vault 配置模板（Shamir 解封）
├── vault-awskms-ha.hcl       # Vault 配置模板（AWS KMS 解封）
├── .env.example              # 环境变量模板
├── .env                      # 环境变量（每节点不同，不提交 Git）
├── setup-ha.sh               # 部署脚本
├── DEPLOY_HA.md              # 本文档
├── config/                   # [自动生成] Vault 运行配置
│   └── vault.hcl
├── tls/                      # TLS 证书
│   ├── ca.pem                # CA 证书（所有节点相同）
│   ├── ca-key.pem            # CA 私钥（所有节点相同）
│   ├── cert.pem              # 节点证书（每节点不同）
│   └── key.pem               # 节点私钥（每节点不同）
├── plugins/                  # 插件二进制（linux/amd64）
├── logs/                     # 审计日志
├── backups/                  # Raft 快照备份
└── vault-init-keys.json      # [仅节点 1] 初始化密钥
```

---

## 部署流程

### 第一步：准备（所有节点）

在每台服务器上：

```bash
# 获取项目代码（或只复制 deploy_ha 目录）
git clone <repo-url>
cd deploy_ha

# 创建 .env 并配置
cp .env.example .env
vim .env
```

**各节点 .env 差异对照：**

| 变量 | 节点 1 | 节点 2 | 节点 3 |
|------|--------|--------|--------|
| `VAULT_CONTAINER_NAME` | vault-ha-1 | vault-ha-2 | vault-ha-3 |
| `VAULT_DATA_VOLUME` | vault-ha-data-1 | vault-ha-data-2 | vault-ha-data-3 |
| `VAULT_NODE_ID` | vault-1 | vault-2 | vault-3 |
| `VAULT_FQDN` | vault-1.example.com | vault-2.example.com | vault-3.example.com |

以下变量在 **所有节点相同**：

```bash
VAULT_NODE_1_ADDR=https://vault-1.example.com:8200
VAULT_NODE_2_ADDR=https://vault-2.example.com:8200
VAULT_NODE_3_ADDR=https://vault-3.example.com:8200
```

```bash
# 创建目录结构
./setup-ha.sh init-dirs

# 将插件二进制（linux/amd64）复制到 plugins/ 目录
cp /path/to/vault-plugin-crypto-v0.1.0 plugins/
```

### 第二步：生成 CA 证书（节点 1）

仅在 **节点 1** 执行：

```bash
./setup-ha.sh gen-ca
```

### 第三步：分发 CA 并生成节点证书（所有节点）

将节点 1 生成的 CA 文件分发到其他节点：

```bash
# 在节点 1 上，将 CA 文件传输到节点 2 和 3
scp tls/ca.pem tls/ca-key.pem user@vault-2.example.com:deploy_ha/tls/
scp tls/ca.pem tls/ca-key.pem user@vault-3.example.com:deploy_ha/tls/
```

在 **每台节点** 上生成各自的证书：

```bash
./setup-ha.sh gen-cert
```

### 第四步：配置并启动（所有节点）

在 **每台节点** 上：

```bash
# 生成 vault.hcl 配置文件
./setup-ha.sh prepare-config

# 启动 Vault 容器
./setup-ha.sh start
```

此时所有节点状态为 `501 (not initialized)`，节点会通过 `retry_join` 自动尝试寻找 leader。

### 第五步：初始化集群（节点 1）

仅在 **节点 1** 执行：

```bash
./setup-ha.sh vault-init
```

输出示例：
```
[OK] Vault cluster initialized! Keys saved to vault-init-keys.json
===========================================================
  CRITICAL: Securely store vault-init-keys.json NOW!
  It contains the unseal keys and root token.
  Distribute unseal keys to different administrators.
  Delete this file after securely backing up the keys.
===========================================================
Root Token: hvs.xxxxxxxxxxxxx
```

**重要**：安全保管 unseal keys 和 root token。

### 第六步：解封（所有节点）

在 **每台节点** 上执行（使用相同的 unseal keys）：

```bash
./setup-ha.sh vault-unseal
```

每个节点需要输入 3 个 unseal key（默认阈值 3/5）。

> 解封顺序：建议先解封节点 1（已初始化），然后解封节点 2 和 3。
> 节点 2 和 3 解封后会自动通过 retry_join 加入集群。

### 第七步：注册插件（Leader 节点）

在 **Leader 节点** 上执行：

```bash
./setup-ha.sh register-plugin
```

插件注册信息会自动通过 Raft 复制到所有 Follower。

### 第八步：验证集群（任意节点）

```bash
# 查看集群成员
./setup-ha.sh raft-status

# 预期输出：
# Total nodes: 3
#
# Node ID              Address                             Voter    Leader
# -------------------- ----------------------------------- -------- --------
# vault-1              https://vault-1.example.com:8201    yes      <-- leader
# vault-2              https://vault-2.example.com:8201    yes
# vault-3              https://vault-3.example.com:8201    yes

# 查看本节点状态
./setup-ha.sh status
```

---

## 备份与恢复

### 在线备份（推荐）

使用 Raft 快照 API，无需停机。可在任意已解封节点执行：

```bash
./setup-ha.sh backup
# 输出：backups/vault-backup-YYYYMMDD_HHMMSS.snap
```

### 恢复

恢复操作会影响 **整个集群**：

```bash
./setup-ha.sh restore backups/vault-backup-20250215_120000.snap
```

恢复后所有节点可能需要重新解封（Shamir 模式）。

### 自动备份

```bash
# crontab 示例：每天凌晨 2 点在 leader 上备份
0 2 * * * cd /path/to/deploy_ha && VAULT_TOKEN=hvs.xxx ./setup-ha.sh backup
```

---

## 日常运维

### 重启单个节点

```bash
# 在目标节点上
./setup-ha.sh stop
./setup-ha.sh start
./setup-ha.sh vault-unseal  # Shamir 模式需要重新解封
```

如果重启的是 Leader，集群会自动选举新 Leader。

### 替换故障节点

1. 在新服务器上部署 `deploy_ha/` 并配置 `.env`（使用新的 VAULT_NODE_ID）
2. 复制 CA 证书，生成新节点证书
3. `prepare-config` → `start` → `vault-unseal`
4. 新节点通过 `retry_join` 自动加入集群
5. （可选）从 Raft 中移除旧节点：
   ```bash
   VAULT_TOKEN=hvs.xxx curl --cacert tls/ca.pem -X POST \
     -d '{"server_id":"old-vault-id"}' \
     https://leader:8200/v1/sys/storage/raft/remove-peer
   ```

### 查看审计日志

```bash
docker compose -f docker-compose.ha.yml logs -f
```

---

## 故障转移

| 场景 | 影响 | 恢复方式 |
|------|------|---------|
| 1 节点宕机 | 集群正常运行（2/3 quorum） | 重启节点 + 解封 |
| 2 节点宕机 | 集群不可用（丢失 quorum） | 恢复至少 1 个节点 + 解封 |
| 3 节点全部宕机 | 集群不可用 | 逐个重启 + 解封 |
| Leader 宕机 | 自动选举新 Leader（几秒） | 透明切换 |
| 网络分区 | 多数侧正常，少数侧只读 | 恢复网络 |

**最低存活节点数：2（3 节点集群）**

---

## 安全加固清单

- [ ] 所有节点启用 TLS（集群通信强制要求）
- [ ] 使用正式 CA 证书（非自签名）用于生产
- [ ] 初始化完成后撤销 Root Token：`vault token revoke <root-token>`
- [ ] Unseal Keys 分发给不同管理员，物理隔离保管
- [ ] 配置 Vault 策略（最小权限）
- [ ] 启用审计日志
- [ ] 防火墙仅开放 8200/8201 给必要来源
- [ ] 服务器间使用内网通信
- [ ] 定期轮换 TLS 证书
- [ ] 每日自动备份（Raft 快照）
- [ ] 定期测试恢复流程
- [ ] 监控集群健康状态（Prometheus + `/v1/sys/health`）
