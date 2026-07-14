# Vault 加密钱包插件 - HA 集群部署指南（AWS 单 AZ · 3 节点 · Shamir）

## 目录

- [前置条件](#前置条件)
- [架构概述](#架构概述)
- [节点数怎么选](#节点数怎么选)
- [AWS 单 AZ 部署](#aws-单-az-部署)
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
- [灾难恢复](#灾难恢复)
- [安全加固清单](#安全加固清单)

---

## 前置条件

| 依赖 | 要求 | 说明 |
|------|------|------|
| 服务器 | 3 台 | 3 台 EC2，同一 AZ |
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

## 节点数怎么选

Vault 整合存储用 Raft 共识，可用的**投票节点必须超过半数**集群才能工作（quorum = ⌊N/2⌋ + 1）。所以节点数只能取奇数：

| 节点数 | Quorum | 可容忍故障 | 评价 |
|--------|--------|-----------|------|
| 1 | 1 | 0 | 开发 / 测试，**无 HA** |
| 2 | 2 | 0 | ❌ **绝不要用**：故障面翻倍却一台都挂不起 |
| **3** | 2 | 1 | ✅ HA 的最小生产基线（**推荐起点**） |
| 4 | 3 | 1 | ❌ 容错和 3 一样，更贵更慢 |
| **5** | 3 | 2 | ✅ 关键业务，容忍 2 台同时故障 |

**只用奇数（1/3/5），永远别用偶数。** 超过 5 台投票节点写入延迟会上升，再扩展请用 performance standby（非投票节点）。

### 本部署：单 AZ 3 节点

本指南部署 **3 节点，且 3 台都在同一个可用区（AZ）**。容错边界要分清：

- ✅ **扛得住**：单台实例故障（硬件 / 实例崩溃 / 重启）—— Raft quorum 2/3 仍满足，集群继续服务
- ❌ **扛不住**：整个 AZ 故障（断电 / 网络隔离）—— 3 台一起失联

> **想抵御 AZ 级故障？** 把 3 台分到 3 个不同 AZ 即可，本套工具链与配置无需改动，只是把实例放到不同子网。代价是跨 AZ 复制有少量延迟与数据传输费。

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

## AWS 单 AZ 部署

本章描述在 AWS 上手动准备 3 台 EC2 的基础设施；准备好后再回到 [部署流程](#部署流程) 用 `setup-ha.sh` 部署。节点间地址方案采用**私网 IP 直连**；客户端接入可选**直连 3 节点**或**内网 NLB 统一入口**，见下文 §5。

### 1. 网络与实例

| 项 | 配置 |
|----|------|
| VPC | 1 个（已有或新建） |
| 子网 | 1 个私有子网（单 AZ，例如 `us-east-1a`） |
| EC2 | 3 台，同一 AZ |
| 实例规格 | 内存敏感，建议 `m5.large`（2 vCPU / 8 GiB）量级起步，按负载调整 |
| AMI | Amazon Linux 2023 或 Ubuntu 22.04+ |
| 软件 | Docker Engine 20.10+ 与 Docker Compose V2 |

**主机准备（每台）**：

- 关闭 swap（Vault 用 mlock 防止密钥被换出到磁盘）：`sudo swapoff -a`，并从 `/etc/fstab` 移除 swap 条目
- `docker-compose.ha.yml` 已声明 `cap_add: IPC_LOCK`，配合配置里的 `disable_mlock = false`，无需额外设置

### 2. 存储（EBS）

每台 EC2 额外挂一块 **gp3 EBS** 卷给 Raft 数据：

- 卷对应 docker 卷 `vault-data`（compose 映射到容器 `/vault/data`）
- 开启 **EBS 静态加密**（AWS KMS 默认或自定义 key）
- 容量：Raft 在**每个**节点都存全量数据，按数据规模 + 快照增长预留（起步 ≥ 20 GiB）

### 3. 安全组

3 台 EC2 用同一个安全组 `sg-vault`：

| 方向 | 端口 | 协议 | 来源 / 目标 | 用途 |
|------|------|------|-------------|------|
| 入站 | 8200 | TCP | 客户端 / 应用 SG；走 NLB 时另加 NLB 的 SG | Vault API（含 NLB 健康检查） |
| 入站 | 8201 | TCP | `sg-vault` 自身 | Raft 集群通信（仅节点间） |
| 入站 | 22 | TCP | 堡垒机 SG（或不开，用 SSM） | 运维登录 |
| 出站 | 443 | TCP | 0.0.0.0/0 | 拉镜像等（按需收紧） |

> 8201 用**安全组自引用**（来源填 `sg-vault` 自己），只有集群内节点能互联，外部访问不到 Raft 端口。

### 4. 地址与证书（私网 IP）

本指南用**私网 IP** 作为节点地址。关键点：**TLS 对 IP 的校验走证书 SAN 的 `IP:` 项**，所以每台证书 SAN 必须含自己的私网 IP，否则节点间 Raft 与客户端连接都会 TLS 失败。

每台 `.env` 按本节点私网 IP 设置（示例为节点 1）：

```bash
VAULT_FQDN=10.0.1.10           # 本节点私网 IP
VAULT_SAN_IP=10.0.1.10         # 写入证书 SAN 的 IP（必填）
# VAULT_SAN_DNS=vault.internal # 走 NLB 时必填：LB 的固定域名，所有节点相同（见 §5 方案 B）

VAULT_NODE_1_ADDR=https://10.0.1.10:8200
VAULT_NODE_2_ADDR=https://10.0.1.11:8200
VAULT_NODE_3_ADDR=https://10.0.1.12:8200
```

`setup-ha.sh gen-cert` 会据 `VAULT_SAN_IP` 把 `IP:10.0.1.x` 写进证书 SAN。同一 VPC 内私网 IP 可直接互通。

> 也可改用 Route53 私有托管区给每台分配 DNS 名（如 `vault-1.internal`）；用 DNS 名则无需 IP SAN、`VAULT_SAN_IP` 可留空。本指南按私网 IP 走。

### 5. 客户端访问（直连或 NLB）

两种接入方式二选一。它们依赖同一个机制：**standby 节点默认把请求经 8201 自动转发给 leader**，所以命中任意一个健康且已解封的节点都能正常读写，客户端 / LB 无需感知谁是 leader。

#### 方案 A：直连 3 节点（无 LB，零额外成本）

- 客户端配置**全部 3 个节点地址** `https://<私网IP>:8200`，并信任集群 CA（`ca.pem`）
- **没有 LB，客户端需自己做失败重试**：某节点 sealed（HTTP 503）或不可达时，换下一个地址重试
- 节点证书 SAN 已含私网 IP，客户端 HTTPS 直接校验通过

#### 方案 B：内网 NLB 统一入口

```
clients ──▶ NLB（TCP :8200 直通，不解密）──▶ vault-1 / vault-2 / vault-3
```

客户端只配一个地址，sealed / 宕机节点由健康检查自动摘除，无需在客户端写重试逻辑。多客户端接入时推荐。

**NLB 与 target group 配置：**

| 项 | 配置 |
|----|------|
| 负载均衡器 | Network Load Balancer，**internal**（内网型），创建时挂好安全组（事后不能补挂） |
| 监听器 | TCP :8200 → target group（**TLS 直通**，LB 不解密，端到端 TLS 与 CA 均不变） |
| Target group | 协议 TCP，端口 8200，target type `instance`，注册 3 台 EC2 |
| 健康检查协议 | HTTPS（LB 健康检查**不校验证书**，自签 CA 无碍） |
| 健康检查端口 | traffic-port（8200） |
| 健康检查路径 | `/v1/sys/health?standbyok=true` |
| 间隔 / 阈值 | 10 秒，健康 / 不健康阈值各 2 次 |

健康检查按 `/v1/sys/health` 的返回码判定（NLB 默认 200–399 视为健康）：

| 返回码 | 节点状态 | 判定 |
|--------|---------|------|
| 200 | leader；带 `standbyok=true` 时 standby 也返回 200 | ✅ 留在池内 |
| 429 | standby（不带 `standbyok`） | ❌ 摘除 |
| 501 | 未初始化 | ❌ 摘除 |
| 503 | sealed | ❌ 摘除 |

路径带不带 `standbyok=true` 是两种策略：

- **带（推荐）**：3 个已解封节点全部接流量，standby 收到请求自动转发给 leader（多一跳内网转发，延迟可忽略），leader 切换对客户端完全透明
- **不带**：只有 leader 留在池内，省一跳转发；代价是 leader 切换后要等健康检查翻转（约 间隔 × 阈值 ≈ 20 秒）入口才恢复

**证书 SAN（必须改）**：客户端经 LB 域名访问，TLS 校验的是该域名，所以**每台节点**的证书 SAN 都必须包含它。建议在 Route53 私有托管区给 NLB 配固定别名（如 `vault.internal`），证书写这个名字，将来换 LB 不用重签。生成证书前在**所有节点**的 `.env` 设置：

```bash
VAULT_SAN_DNS=vault.internal   # 多个域名用逗号分隔（不要空格，或整体加引号）
```

`gen-cert` 会把 `DNS:vault.internal` 一并写入 SAN。客户端照常信任 `ca.pem`，地址换成 `https://vault.internal:8200`。

已运行的集群补加 NLB：重签证书后用 SIGHUP 热重载（Vault 会重新加载 listener 的 TLS 证书，**不会 seal**，无需重新解封）：

```bash
# 每台节点执行：
vim .env                        # 加 VAULT_SAN_DNS=...
rm tls/cert.pem tls/key.pem
./setup-ha.sh gen-cert          # 检测到本节点容器在运行时，会自动修正新证书属主

docker compose -f docker-compose.ha.yml --env-file .env kill -s HUP vault

# 验证已生效：输出应包含 VAULT_SAN_DNS 里的域名
echo | openssl s_client -connect 127.0.0.1:8200 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

> **属主背景**：容器启动时的 `chown -R vault:vault /vault/tls` 只执行一次；运行中重签的文件属主是执行 `gen-cert` 的用户（通常 root）且权限 600，容器内 vault 进程读不了 → SIGHUP 重载失败、**静默保留旧证书**。`gen-cert` 会在检测到容器运行时自动 `docker exec` 修正属主；若它提示 chown 失败，先手动执行再重载：
>
> ```bash
> docker compose -f docker-compose.ha.yml --env-file .env exec vault \
>   chown vault:vault /vault/tls/cert.pem /vault/tls/key.pem
> ```
>
> 若 SAN 仍是旧的，用 `docker logs <容器名> 2>&1 | grep -iE "reload|permission"` 查看重载报错。

**保持直连、不进 LB 的部分：**

- 8201（Raft 集群通信）：节点间直连，LB 只挂 8200
- `retry_join` / `api_addr` / `cluster_addr`：继续用各节点私网 IP，**不要指向 LB**
- 运维操作（`vault-init` / `vault-unseal` / `raft-status` / 备份 cron）：仍在各节点本机执行
- 安全组：8200 入站在客户端来源之外**另加 NLB 的安全组**（健康检查的来源；若 NLB 未挂 SG 则放行其子网网段）。NLB `instance` target 默认保留客户端源 IP，审计日志仍是真实来源，客户端来源规则保持不变

> NLB 不改变解封运维：Shamir 模式下节点重启后仍需人工 `vault-unseal`，LB 只是让 sealed 期间的流量自动绕开该节点。

### 6. 架构（单 AZ）

```
                       Region: us-east-1
           ┌──────── Availability Zone: us-east-1a ─────────┐
           │                                                │
           │  EC2 #1 10.0.1.10   EC2 #2 10.0.1.11   EC2 #3 10.0.1.12
           │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
  clients ─┼─▶│ Vault+crypto│   │ Vault+crypto│   │ Vault+crypto│
 (直连3地址)│  │ Raft + gp3  │   │ Raft + gp3  │   │ Raft + gp3  │
           │  │ :8200 :8201 │   │ :8200 :8201 │   │ :8200 :8201 │
           │  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
           │         └──── Raft (TLS, :8201, sg 自引用) ───┘
           └────────────────────────────────────────────────┘
  ⚠ 单 AZ：扛单实例故障，不扛整个 AZ 故障
```

> 采用 NLB（§5 方案 B）时，clients → 内网 NLB → 3 节点，图中其余部分不变。

### 7. Shamir 解封在 AWS 上的注意事项

本指南用 Shamir 手动解封，在云上有几个运维点：

- **每次重启 / 换实例都要人工解封**：节点重启后是 sealed 状态，需有人执行 `./setup-ha.sh vault-unseal` 输入 3 个 unseal key。准备 break-glass 流程，明确谁持有 key、如何快速解封。
- **不要用 Auto Scaling Group**：新实例起来是 sealed 的，无法自动加入服务。本部署用**固定实例**。
- **快照异地备份**：把 Raft 快照推到 S3 留存：
  ```bash
  aws s3 cp backups/vault-backup-YYYYMMDD_HHMMSS.snap \
    s3://your-bucket/vault-snapshots/ --sse aws:kms
  ```
  给该 S3 前缀配生命周期策略做保留 / 过期。
- **将来想免人工解封**：可切换到 AWS KMS 自动解封（已有模板 `vault-awskms-ha.hcl`），重启 / 扩缩容无需手动输 key。注意自动解封下 `init` 拿到的是 **recovery key** 而非 unseal key。

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

**各节点 .env 差异对照：**（AWS 私网 IP 部署：`VAULT_FQDN` 与 `VAULT_SAN_IP` 均填各节点私网 IP，详见上文「AWS 单 AZ 部署」§4）

| 变量 | 节点 1 | 节点 2 | 节点 3 |
|------|--------|--------|--------|
| `VAULT_CONTAINER_NAME` | vault-ha-1 | vault-ha-2 | vault-ha-3 |
| `VAULT_DATA_VOLUME` | vault-ha-data-1 | vault-ha-data-2 | vault-ha-data-3 |
| `VAULT_NODE_ID` | vault-1 | vault-2 | vault-3 |
| `VAULT_FQDN` | 10.0.1.10 | 10.0.1.11 | 10.0.1.12 |
| `VAULT_SAN_IP` | 10.0.1.10 | 10.0.1.11 | 10.0.1.12 |

以下变量在 **所有节点相同**：

```bash
VAULT_NODE_1_ADDR=https://10.0.1.10:8200
VAULT_NODE_2_ADDR=https://10.0.1.11:8200
VAULT_NODE_3_ADDR=https://10.0.1.12:8200

# 走 NLB 方案时再加（所有节点相同，见「AWS 单 AZ 部署」§5 方案 B）
# VAULT_SAN_DNS=vault.internal
```

```bash
# 创建目录结构
./setup-ha.sh init-dirs

# 将插件二进制（linux/amd64）复制到 plugins/ 目录
cp /path/to/vault-plugin-crypto-v0.2.0 plugins/
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

> 本指南采用 **Shamir 手动解封**。若改用 AWS KMS 自动解封（`vault-awskms-ha.hcl`），节点启动会自动解封，`init` 得到的是 recovery key 而非 unseal key，本步骤可跳过。

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

快照成功后该命令还会做两件事：

1. 若 `.env` 开启了 `BACKUP_S3_ENABLED=true`，把快照上传到 S3（见 [备份到 S3（可选）](#备份到-s3可选)）；
2. 清理本地超过 `BACKUP_LOCAL_RETENTION_DAYS`（默认 14 天）的旧快照，`backups/backup.token` 不受影响。

### 恢复（同一集群内回滚）

恢复操作会影响 **整个集群**：

```bash
./setup-ha.sh restore backups/vault-backup-20250215_120000.snap
```

恢复后所有节点可能需要重新解封（Shamir 模式）。

> `restore` 会让 Vault 校验快照的 seal 一致性，**拒绝**来自其他集群的快照。这层保护是有意保留的，防止误把 A 集群的快照灌进 B 集群。
>
> 集群整体损毁、要在全新服务器上重建时，这个校验必然失败（新集群的 Shamir key 不可能和快照匹配）。那种情况见 [灾难恢复](#灾难恢复)。

### 验证恢复结果

恢复完成后，除了 `raft-status` 看集群成员，还应确认插件数据真的回来了：

```bash
# 列出所有 key 的 external_id
./setup-ha.sh list-keys

# 抽查一个 key 的详情
./setup-ha.sh key-info wallet:eth:main
```

`key-info` 是比 `list-keys` 更强的验证：插件每次读取都会**从存储的私钥现算 public_key**，所以它能返回正确的公钥，就证明 key 材料被 Vault 的 barrier key 正确解密了 —— 而不只是「条目还在」。

两个命令都读 `PLUGIN_MOUNT_PATH`（默认 `crypto`），需要一个对该挂载点有 list / read 权限的 token。

### 自动备份

自动备份**不要用 root token**。用下面的命令生成一个**最小权限、可续期**的专用 token（纯 HTTP API，**无需安装 vault CLI**）：

```bash
# 在 leader 上运行，按提示输入 root token（或先 export VAULT_TOKEN=<root>）
./setup-ha.sh gen-backup-token
```

它会：

1. 写入策略 `raft-snapshot`——只允许读取 Raft 快照 + 查询/续期自身 token：
   ```hcl
   path "sys/storage/raft/snapshot" { capabilities = ["read"] }
   path "auth/token/lookup-self"    { capabilities = ["read"] }
   path "auth/token/renew-self"     { capabilities = ["update"] }
   ```
   > `lookup-self` 和 `renew-self` **不是** ACL 豁免路径，它们的权限来自 Vault 内置的 `default` 策略。本 token 用 `no_default_policy` 关掉了 default，所以这两条必须显式授予。
2. 创建一个绑定该策略的 **periodic**（`period=720h`）**orphan** token，并去掉默认策略；
3. 打印 token 并写入 `backups/backup.token`（权限 `600`）。

该 token 是 periodic，需定期续期才不过期；续期失败不阻断当次备份。先在 `deploy_ha/` 下建一个包装脚本：

```bash
cat > cron-backup.sh <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

T=$(cat backups/backup.token)

# 尽力续期（失败不阻断当次备份）
curl -sf --cacert tls/ca.pem -H "X-Vault-Token: $T" \
  -X POST https://127.0.0.1:8200/v1/auth/token/renew-self -o /dev/null \
  || echo "[warn] token renew-self failed, continuing with backup"

VAULT_TOKEN=$T ./setup-ha.sh backup
EOF
chmod 700 cron-backup.sh
```

再配置 crontab —— **整条命令必须写在一行**，cron 不支持反斜杠续行：

```cron
# 每小时整点在 leader 上执行
0 * * * * /path/to/deploy_ha/cron-backup.sh >> /path/to/deploy_ha/logs/backup.log 2>&1
```

每小时一次快照不会撑爆磁盘：每次备份成功后自动删除本地 14 天前的旧快照（`.env` 中 `BACKUP_LOCAL_RETENTION_DAYS` 可调，设 `0` 关闭清理）。

> ⚠️ cron 的每一行都是一条独立任务，行尾的 `\` **不会**续接下一行；换行后的内容会被当成新任务的分钟字段，报 `bad minute`。
>
> ⚠️ crontab 中的 `%` 是特殊字符（会被转成换行），命令里若需要 `%`（如 `date +%F`）必须写成 `\%`。把命令放进脚本可一并规避这两个坑。

> `TLS_DISABLE=true` 时把脚本里的 `https://` 改为 `http://` 并去掉 `--cacert tls/ca.pem`。

### 备份到 S3（可选）

开启后，`backup` 命令在本地快照成功后调用 aws CLI 把快照推送到 S3，按日期分目录存放：

```
s3://<bucket>/[prefix/]YYYY/MM/DD/vault-backup-YYYYMMDD_HHMMSS.snap
# 例如 s3://my-vault-backups/vault-ha/2026/07/13/vault-backup-20260713_140000.snap
```

在 `.env` 中配置：

```bash
BACKUP_S3_ENABLED=true
BACKUP_S3_BUCKET=my-vault-backups
# 可选：对象 key 前缀、bucket 所在区域
# BACKUP_S3_PREFIX=vault-ha
# BACKUP_S3_REGION=us-east-1
```

前提条件：

- 节点上已安装 aws CLI（`aws --version` 能运行即可，v1/v2 均支持）；
- 凭证走 AWS 标准链，按顺序：`.env` 中的 `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`（若为 KMS 解封配置过会被一并复用）→ `~/.aws/credentials` → EC2 实例角色（**推荐**，免密钥落盘）。所用身份只需对 bucket 有 `s3:PutObject`：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::my-vault-backups/*"
  }]
}
```

行为约定：

- 上传失败**不影响本地快照**（文件保留），命令以非零退出并在 `logs/backup.log` 留下 `[ERROR]`，便于监控发现；
- 上传失败时本地清理照常执行，避免 S3 配置坏掉后磁盘被每小时的快照塞满；
- **S3 上的快照永不被脚本删除**。如需过期归档/清理，用 S3 生命周期规则（Lifecycle）自行配置，例如 90 天后转 Glacier。

> Raft 快照包含 Vault 全部加密数据（由 barrier key 加密，S3 上无法解密），但泄露仍有风险。bucket 应开启 **阻止公共访问 + 默认加密（SSE-S3/SSE-KMS）**，并限制读取权限。

### 查看 token 有效期

```bash
# 查看备份 token（读 backups/backup.token）
./setup-ha.sh token-status --backup-token

# 查看任意 token（交互式输入，不回显）
./setup-ha.sh token-status
```

输出示例：

```
=== Token Status ===

  Display name:  token-raft-snapshot-backup
  Accessor:      hmac-abc...
  Policies:      raft-snapshot
  Orphan:        True
  Renewable:     True
  Issued at:     2026-07-09T02:00:00Z

  TTL remaining: 29d 23h 43m  (2591000s)
  Expires at:    2026-08-08T02:00:00Z
  Period:        30d  (renew-self resets TTL back to this)
  Max TTL:       unlimited (no explicit max)
```

| 字段 | 含义 |
|------|------|
| `TTL remaining` | 距离过期还剩多久（每次 `renew-self` 成功后重置回 `Period`） |
| `Period` | periodic token 的续期周期，备份 token 为 `30d`（720h） |
| `Max TTL` | `unlimited` 表示无硬性上限，可无限续期 |
| `Renewable` | 为 `false` 时 token 到期即失效，无法延长 |

命令会在异常时给出 `[WARN]` 提示，最需要留意这条：

- **`TTL is below half the period`** —— 说明 cron 里的续期一直在失败。去 `logs/backup.log` 里 grep `token renew-self failed` 确认。

#### HTTP 403 怎么办

Vault 对「token 无效」和「token 有效但无权限」返回的都是 `permission denied`，所以 403 有两种可能：

**a) token 已过期 / 被吊销** —— 重新生成：`./setup-ha.sh gen-backup-token`

**b) token 的策略没有 `auth/token/lookup-self` 的 read 权限** —— 这条规则是后加的，早于它签发的备份 token 会命中此情况。典型特征是 **`backup` 能跑通，但 `token-status` 报 403**。

情况 b 不需要重签 token，策略是**按名字在每次请求时解析**的，改策略即刻对已签发的 token 生效：

```bash
# 只重写 raft-snapshot 策略，不动现有 token（需 root token）
./setup-ha.sh gen-backup-token --policy-only

# 然后再查一次
./setup-ha.sh token-status --backup-token
```

> `auth/token/lookup-self` 的 read 权限来自 Vault 内置的 `default` 策略（见 Vault 源码 `vault/policy_store.go` 的 `defaultPolicy`），它**不是** ACL 豁免路径。备份 token 用 `no_default_policy` 关掉了 default，所以必须在 `raft-snapshot` 策略里显式授予 —— 和 `renew-self` 同理。
>
> token 只从交互式输入、`VAULT_TOKEN` 环境变量或 `backups/backup.token` 读取，**不接受命令行参数** —— 否则 token 会出现在 `ps` 输出和 shell history 里。

> 若环境已安装 vault CLI，也可等价手动创建（策略同上三条）：
> ```bash
> vault policy write raft-snapshot - <<'EOF'
> path "sys/storage/raft/snapshot" { capabilities = ["read"] }
> path "auth/token/lookup-self"    { capabilities = ["read"] }
> path "auth/token/renew-self"     { capabilities = ["update"] }
> EOF
> vault token create -policy=raft-snapshot -period=720h -orphan -no-default-policy
> ```

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
| 3 台服务器**永久损毁** | 数据仅存于快照 | 见 [灾难恢复](#灾难恢复) |
| Leader 宕机 | 自动选举新 Leader（几秒） | 透明切换 |
| 网络分区 | 多数侧正常，少数侧只读 | 恢复网络 |

**最低存活节点数：2（3 节点集群）**

---

## 灾难恢复

三台服务器全部永久损毁（实例被销毁、EBS 卷丢失、整个 AZ 不可恢复）时，在全新服务器上重建集群的流程。

### 先决条件：缺一不可

Shamir 模式下，快照里的数据是用**旧集群的 master key** 加密的。恢复的前提是你同时持有以下三样：

| # | 东西 | 存放位置 | 丢失后果 |
|---|------|---------|---------|
| 1 | **快照文件** `.snap` | **必须在三台机器之外**（如 S3） | 数据全部丢失 |
| 2 | **旧集群的 unseal keys** | `vault-init-keys.json`，分发给不同管理员 | 快照是无法解密的砖，**无任何补救手段** |
| 3 | **旧集群的 root token** | 同上 | 需要另有高权限 token |

第 2 条是**硬约束**。Vault 源码 `vault/raft.go` 的 `raftSnapshotRestoreCallback` 里，恢复后若 keyring 解不开：

```go
case SealConfigTypeShamir:
    // If we are a shamir seal we can't do anything. Just
    // seal all nodes.
```

> 所以「把 unseal keys 和快照存在同一批服务器上」等于没有备份。快照推 S3（见 [Shamir 解封在 AWS 上的注意事项](#7-shamir-解封在-aws-上的注意事项)），unseal keys 离线分发给不同管理员。

### 恢复流程

#### 第一步：拉起一个全新的、临时的集群

在 3 台新服务器上，按 [部署流程](#部署流程) 正常走一遍：

```bash
./setup-ha.sh init-dirs
# 节点 1：./setup-ha.sh gen-ca ，然后把 ca.pem / ca-key.pem 分发到节点 2、3
./setup-ha.sh gen-cert
./setup-ha.sh prepare-config
./setup-ha.sh start

# 节点 1
./setup-ha.sh vault-init      # 产生【临时】unseal keys + root token
# 三台都执行
./setup-ha.sh vault-unseal    # 用【临时】unseal keys
```

要点：

- `.env` 里的 `VAULT_FQDN` / `VAULT_SAN_IP` / `VAULT_NODE_*_ADDR` 换成新机器的私网 IP
- **CA 可以是全新的**，TLS 和 Vault 的数据加密无关
- **node ID 可以复用** `vault-1/2/3`（原因见下方「为什么 peer 配置不会被覆盖」）
- 这一步产生的临时 unseal keys 和 root token，唯一用途是把快照灌进去，灌完即作废
- **不要执行 `register-plugin`** —— 插件注册信息在快照里，会被一起恢复

#### 第二步：强制恢复快照

```bash
# 用【临时】root token
VAULT_TOKEN=<临时 root token> \
  ./setup-ha.sh restore-force backups/vault-backup-YYYYMMDD_HHMMSS.snap
```

命令会要求你输入 `FORCE` 二次确认。它打的是 `sys/storage/raft/snapshot-force` 端点，**绕过** seal 一致性校验 —— 普通的 `restore` 在这里必然失败，Vault 会明确告诉你：

```
could not verify hash file, possibly the snapshot is using a different
set of unseal keys; use the snapshot-force API to bypass this check
```

#### 第三步：用「旧」unseal keys 解封三台

恢复一完成，**三个节点会全部自动 seal**。这是预期行为，不是故障 —— 此刻存储里的 keyring 已经是旧集群的，新集群的 master key 解不开它。

```bash
# 每台都执行，输入【旧集群】的 3 个 unseal key
./setup-ha.sh vault-unseal
```

解封后集群就是旧集群了：**旧 root token 生效，临时的那套彻底作废**。

#### 第四步：验证

```bash
./setup-ha.sh raft-status                 # 3 个节点，1 个 leader
./setup-ha.sh list-keys                   # key 数量应与灾难前一致
./setup-ha.sh key-info <某个 external_id>  # 能算出 public_key = 私钥解密正常
```

#### 第五步：收尾

- 删除新节点 1 上那份**临时**的 `vault-init-keys.json`，避免日后与真正的 keys 混淆
- 备份 token 也在快照里恢复了，但 `backups/backup.token` 文件不在。要么从旧机器的备份里取回该文件，要么重新签发：`./setup-ha.sh gen-backup-token`
- 客户端换用新集群的 `ca.pem`，并把地址指向新的私网 IP

### 两个容易踩的点

**为什么 peer 配置不会被覆盖。** 新集群的三个 node ID 和地址会被保留，不会变回旧集群的 IP。这一点由 `hashicorp/raft` 的 `Restore()` 明确保证：

> We will use the current Raft configuration, not the one from the snapshot, so that we can restore into a new cluster.

**插件二进制必须是同一个。** 插件的注册信息（名字、命令、SHA-256）在快照里会被一起恢复。新机器 `plugins/` 目录下的二进制若 SHA-256 对不上，插件挂载会加载失败，而此时 `register-plugin` 不该重跑。本仓库已将二进制纳入 git 跟踪，checkout 同一个 commit 即可保证一致。

### 演练

**这套流程必须在真实环境演练过，才算数。** 拿 3 台临时机器，用一份真实快照走一遍全流程，确认 `list-keys` 的数量和 `key-info` 的公钥与灾难前一致。别等真出事才第一次执行 —— 那时你会同时面对生产中断和一个没验证过的手册。

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
- [ ] 每小时自动备份（Raft 快照）
- [ ] 快照推送到异地存储（S3），**不与 Vault 节点同生共死**（开启 `BACKUP_S3_ENABLED`，见 [备份到 S3](#备份到-s3可选)）
- [ ] Unseal keys 离线保管，**与快照分开存放**（两者都丢 = 数据永久损毁）
- [ ] 定期演练 [灾难恢复](#灾难恢复) 全流程（含 `restore-force` + 旧 key 解封）
- [ ] 监控集群健康状态（Prometheus + `/v1/sys/health`）
