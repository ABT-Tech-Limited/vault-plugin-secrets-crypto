# deploy_ha AWS 单 AZ 部署指南完善 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `deploy_ha/` 的部署指南在 AWS 单 AZ 3 节点 + Shamir + 私网 IP 直连场景下开箱可用，并修复检查中发现的 bug。

**Architecture:** 方案 A（叠加）——保留现有 DEPLOY_HA.md 通用流程，新增「节点数怎么选」「AWS 单 AZ 部署」两节与运维注意；`.env.example` 修版本号并新增 `VAULT_SAN_IP`；`setup-ha.sh` 的 `gen-cert` 加 ~3 行支持把私网 IP 写入证书 SAN。

**Tech Stack:** Bash（setup-ha.sh）、Docker Compose、HashiCorp Vault（Raft 整合存储、Shamir 解封、TLS）、Markdown、openssl、AWS（EC2 / EBS / 安全组 / spread placement group）。

参考 spec：[docs/superpowers/specs/2026-06-13-deploy-ha-aws-guide-design.md](../specs/2026-06-13-deploy-ha-aws-guide-design.md)

---

## 文件结构

| 文件 | 职责 | 改动 |
|------|------|------|
| `deploy_ha/setup-ha.sh` | 部署辅助脚本 | `cmd_gen_cert` 加 `VAULT_SAN_IP` → IP SAN（~3 行） |
| `deploy_ha/.env.example` | 环境变量模板 | 修 `PLUGIN_VERSION`；新增 `VAULT_SAN_IP` |
| `deploy_ha/DEPLOY_HA.md` | 部署指南 | 新增 2 节 + 运维注意 + 修 crontab/解封小问题 + TOC |

任务顺序：先改可验证的脚本（Task 1），再改配置模板（Task 2），最后分三块写文档（Task 3-5）。

---

### Task 1: gen-cert 支持把私网 IP 写入证书 SAN

**Files:**
- Modify: `deploy_ha/setup-ha.sh`（`cmd_gen_cert`，当前第 140 行附近）

- [ ] **Step 1: 修改 SAN 构建逻辑**

在 [deploy_ha/setup-ha.sh](../../../deploy_ha/setup-ha.sh) 的 `cmd_gen_cert` 中，找到这段：

```bash
  # Collect all node FQDNs for SAN
  local san="DNS:${fqdn},DNS:localhost,IP:127.0.0.1"
```

替换为：

```bash
  # Collect all node FQDNs/IPs for SAN.
  # VAULT_SAN_IP adds the node's private IP as an IP SAN entry — required when
  # peers/clients connect by IP, since TLS verifies IPs against iPAddress SANs
  # (a DNS:<ip> entry does NOT satisfy IP verification).
  local san="DNS:${fqdn},DNS:localhost,IP:127.0.0.1"
  if [ -n "${VAULT_SAN_IP:-}" ]; then
    san="${san},IP:${VAULT_SAN_IP}"
  fi
```

- [ ] **Step 2: 验证 —— 设置 VAULT_SAN_IP 后证书 SAN 含该 IP**

在 `deploy_ha/` 目录下运行（自包含、用完即清理；该目录此前无 `tls/` 与 `.env`）：

```bash
cd deploy_ha
# 备份可能存在的 .env，准备临时测试 env
[ -f .env ] && mv .env .env.realbak
cat > .env <<'EOF'
VAULT_FQDN=10.9.9.9
VAULT_SAN_IP=10.9.9.9
VAULT_NODE_1_ADDR=https://10.9.9.9:8200
VAULT_NODE_2_ADDR=https://10.9.9.10:8200
VAULT_NODE_3_ADDR=https://10.9.9.11:8200
EOF
rm -rf tls
./setup-ha.sh gen-ca
./setup-ha.sh gen-cert
echo "----- SAN -----"
openssl x509 -in tls/cert.pem -noout -text | grep -A1 "Subject Alternative Name"
```

Expected: 在 `X509v3 Subject Alternative Name` 下出现 `IP Address:10.9.9.9`（同时含 `IP Address:127.0.0.1`）。

- [ ] **Step 3: 清理测试产物**

```bash
rm -rf tls .env
[ -f .env.realbak ] && mv .env.realbak .env
cd ..
git status --short deploy_ha   # 应只显示 setup-ha.sh 被修改，无 tls/.env 残留
```

Expected: `git status` 仅显示 ` M deploy_ha/setup-ha.sh`。

- [ ] **Step 4: Commit**

```bash
git add deploy_ha/setup-ha.sh
git commit -m "🔐 feat(deploy_ha): support VAULT_SAN_IP for private-IP cert SAN in gen-cert"
```

---

### Task 2: .env.example 修版本号并新增 VAULT_SAN_IP

**Files:**
- Modify: `deploy_ha/.env.example`

- [ ] **Step 1: 修复 PLUGIN_VERSION 并在 This Node 段加 VAULT_SAN_IP**

在 [deploy_ha/.env.example](../../../deploy_ha/.env.example) 中：

(1) 把：
```bash
PLUGIN_VERSION=v0.1.0
```
改为：
```bash
PLUGIN_VERSION=v0.2.0
```

(2) 在 `# ---------- This Node ----------` 段，`VAULT_FQDN=vault-1.example.com` 之后新增：
```bash
# 本节点私网 IP，写入证书 SAN（AWS 私网 IP 直连必填；改用 DNS 名时可留空）
VAULT_SAN_IP=10.0.1.10
```

- [ ] **Step 2: 验证**

```bash
grep -n "PLUGIN_VERSION=v0.2.0" deploy_ha/.env.example
grep -n "VAULT_SAN_IP" deploy_ha/.env.example
grep -c "PLUGIN_VERSION=v0.1.0" deploy_ha/.env.example   # 期望 0
```

Expected: 前两条各有 1 行命中；第三条输出 `0`。

- [ ] **Step 3: Commit**

```bash
git add deploy_ha/.env.example
git commit -m "🐛 fix(deploy_ha): bump PLUGIN_VERSION to v0.2.0 and add VAULT_SAN_IP"
```

---

### Task 3: 新增「节点数怎么选」一节 + 标题/前置条件/TOC

**Files:**
- Modify: `deploy_ha/DEPLOY_HA.md`

- [ ] **Step 1: 改标题**

把第 1 行：
```markdown
# Vault 加密钱包插件 - HA 集群部署指南（3 节点）
```
改为：
```markdown
# Vault 加密钱包插件 - HA 集群部署指南（AWS 单 AZ · 3 节点 · Shamir）
```

- [ ] **Step 2: TOC 增项**

在 `## 目录` 列表中，`- [架构概述](#架构概述)` 这一行之后新增：
```markdown
- [节点数怎么选](#节点数怎么选)
- [AWS 单 AZ 部署](#aws-单-az-部署)
```

- [ ] **Step 3: 前置条件补 AWS 语境**

在 `## 前置条件` 的表格中，把：
```markdown
| 服务器 | 3 台 | 独立物理机或 VM |
```
改为：
```markdown
| 服务器 | 3 台 | 3 台 EC2，同一 AZ，同一 spread placement group |
```

- [ ] **Step 4: 插入「节点数怎么选」整节**

在 `## 目录结构` 这一行**之前**插入以下整块（即放在「架构概述」与「目录结构」之间）：

```markdown
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

**缓解相关性故障**：把 3 台 EC2 放进同一个 **spread placement group**，AWS 会强制把它们分散到不同的底层硬件 / 机架（单 AZ 内每个 spread group 上限 7 台），避免「三台恰好落在同一宿主机、一损俱损」。这是单 AZ 下能做到的最好实例级隔离。

> **想抵御 AZ 级故障？** 把 3 台分到 3 个不同 AZ 即可，本套工具链与配置无需改动，只是把实例放到不同子网。代价是跨 AZ 复制有少量延迟与数据传输费。

```

- [ ] **Step 5: 验证**

```bash
grep -n "## 节点数怎么选" deploy_ha/DEPLOY_HA.md
grep -n "AWS 单 AZ · 3 节点 · Shamir" deploy_ha/DEPLOY_HA.md
grep -n "spread placement group" deploy_ha/DEPLOY_HA.md
grep -n "永远别用偶数" deploy_ha/DEPLOY_HA.md
```

Expected: 标题行命中；「节点数怎么选」节命中；后两条各有命中。

- [ ] **Step 6: Commit**

```bash
git add deploy_ha/DEPLOY_HA.md
git commit -m "📝 docs(deploy_ha): add node-count/quorum section and single-AZ framing"
```

---

### Task 4: 新增「AWS 单 AZ 部署」章节（含 Shamir 运维注意）

**Files:**
- Modify: `deploy_ha/DEPLOY_HA.md`

- [ ] **Step 1: 在「部署流程」之前插入 AWS 章节**

在 `## 部署流程` 这一行**之前**插入以下整块：

````markdown
## AWS 单 AZ 部署

本章描述在 AWS 上手动准备 3 台 EC2 的基础设施；准备好后再回到 [部署流程](#部署流程) 用 `setup-ha.sh` 部署。地址方案采用**私网 IP 直连**，客户端直连节点（不使用负载均衡器）。

### 1. 网络与实例

| 项 | 配置 |
|----|------|
| VPC | 1 个（已有或新建） |
| 子网 | 1 个私有子网（单 AZ，例如 `us-east-1a`） |
| EC2 | 3 台，同一 AZ，同一 **spread placement group** |
| 实例规格 | 内存敏感，建议 `m5.large`（2 vCPU / 8 GiB）量级起步，按负载调整 |
| AMI | Amazon Linux 2023 或 Ubuntu 22.04+ |
| 软件 | Docker Engine 20.10+ 与 Docker Compose V2 |

创建 spread placement group（一次）：

```bash
aws ec2 create-placement-group \
  --group-name vault-ha-spread \
  --strategy spread
```

启动 3 台 EC2 时带上 `--placement "GroupName=vault-ha-spread"`，确保落在不同硬件。

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
| 入站 | 8200 | TCP | 客户端 / 应用 SG | Vault API |
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

VAULT_NODE_1_ADDR=https://10.0.1.10:8200
VAULT_NODE_2_ADDR=https://10.0.1.11:8200
VAULT_NODE_3_ADDR=https://10.0.1.12:8200
```

`setup-ha.sh gen-cert` 会据 `VAULT_SAN_IP` 把 `IP:10.0.1.x` 写进证书 SAN。同一 VPC 内私网 IP 可直接互通。

> 也可改用 Route53 私有托管区给每台分配 DNS 名（如 `vault-1.internal`）；用 DNS 名则无需 IP SAN、`VAULT_SAN_IP` 可留空。本指南按私网 IP 走。

### 5. 客户端访问（直连，无负载均衡）

客户端（你的应用）**直连节点**，不经 LB：

- 客户端配置**全部 3 个节点地址** `https://<私网IP>:8200`，并信任集群 CA（`ca.pem`）
- Vault standby 节点默认会把请求**转发给 leader**，所以命中任意一个**健康且已解封**的节点都能正常读写
- **没有 LB，客户端需自己做失败重试**：某节点 sealed（HTTP 503）或不可达时，换下一个地址重试
- 节点证书 SAN 已含私网 IP，客户端 HTTPS 直接校验通过

### 6. 架构（单 AZ）

```
                       Region: us-east-1
           ┌──────── Availability Zone: us-east-1a ─────────┐
           │        Spread Placement Group: vault-ha        │
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
````

- [ ] **Step 2: 验证**

```bash
grep -n "## AWS 单 AZ 部署" deploy_ha/DEPLOY_HA.md
grep -n "create-placement-group" deploy_ha/DEPLOY_HA.md
grep -n "安全组自引用" deploy_ha/DEPLOY_HA.md
grep -n "客户端需自己做失败重试" deploy_ha/DEPLOY_HA.md
grep -n "aws s3 cp" deploy_ha/DEPLOY_HA.md
grep -n "## 部署流程" deploy_ha/DEPLOY_HA.md   # 确认仍在、且位于 AWS 章节之后
```

Expected: AWS 章节标题命中；placement group、安全组自引用、客户端失败重试、S3 快照各有命中；`## 部署流程` 仍存在。

- [ ] **Step 3: Commit**

```bash
git add deploy_ha/DEPLOY_HA.md
git commit -m "📝 docs(deploy_ha): add AWS single-AZ deployment chapter with Shamir ops notes"
```

---

### Task 5: 小问题修复（crontab 受限 token、解封声明）+ 全文一致性校验

**Files:**
- Modify: `deploy_ha/DEPLOY_HA.md`

- [ ] **Step 1: 解封步骤加 Shamir 声明**

在 `### 第六步：解封（所有节点）` 标题下、第一段说明之后，新增一行引用块：

```markdown
> 本指南采用 **Shamir 手动解封**。若改用 AWS KMS 自动解封（`vault-awskms-ha.hcl`），节点启动会自动解封，`init` 得到的是 recovery key 而非 unseal key，本步骤可跳过。
```

- [ ] **Step 2: crontab 备份改用最小权限 token**

把「自动备份」小节中的：

```markdown
### 自动备份

```bash
# crontab 示例：每天凌晨 2 点在 leader 上备份
0 2 * * * cd /path/to/deploy_ha && VAULT_TOKEN=hvs.xxx ./setup-ha.sh backup
```
```

替换为：

````markdown
### 自动备份

先创建一个**最小权限**的备份策略与专用 token（不要用 root token）：

```bash
# 备份策略：只允许读取 Raft 快照
vault policy write raft-snapshot - <<'EOF'
path "sys/storage/raft/snapshot" {
  capabilities = ["read"]
}
EOF

# 生成长期 token 专供备份用
vault token create -policy=raft-snapshot -period=720h -orphan
```

```bash
# crontab：每天凌晨 2 点在 leader 上备份（用上面的受限 token，切勿用 root）
0 2 * * * cd /path/to/deploy_ha && VAULT_TOKEN=hvs.<backup-token> ./setup-ha.sh backup
```
````

- [ ] **Step 3: 全文一致性校验（无残留旧表述、无明文 root token）**

```bash
# 不应再有「需要 root token 的 crontab 明文」——确认 backup crontab 用的是 <backup-token>
grep -n "VAULT_TOKEN=hvs.xxx ./setup-ha.sh backup" deploy_ha/DEPLOY_HA.md   # 期望 0 命中
# 不应把 NLB / 跨 AZ / Route53 当作主路径（本指南是直连 + 单 AZ + 私网 IP）
grep -niE "负载均衡器|NLB" deploy_ha/DEPLOY_HA.md    # 仅允许出现在「无负载均衡」语境
grep -n "raft-snapshot" deploy_ha/DEPLOY_HA.md       # 备份策略片段已落地
grep -n "Shamir 手动解封" deploy_ha/DEPLOY_HA.md      # 解封声明已落地
```

Expected: 第一条 `0` 命中；`raft-snapshot`、`Shamir 手动解封` 有命中；NLB 仅出现在「无负载均衡 / 不引入 NLB」这类否定语境。

- [ ] **Step 4: 渲染快速目检**

```bash
# 确认新章节顺序：节点数怎么选 → 目录结构 → AWS 单 AZ 部署 → 部署流程
grep -nE "^## (节点数怎么选|目录结构|AWS 单 AZ 部署|部署流程)" deploy_ha/DEPLOY_HA.md
```

Expected: 四个标题按上述顺序出现（行号递增）。

- [ ] **Step 5: Commit**

```bash
git add deploy_ha/DEPLOY_HA.md
git commit -m "📝 docs(deploy_ha): scope backup token, add Shamir unseal note, consistency pass"
```

---

## 完成后

- 5 个提交全部落在分支 `docs/aws-ha-deploy-guide`
- 用 [superpowers:finishing-a-development-branch] 决定合并 / PR
- 可选：人工通读 DEPLOY_HA.md 一遍，确认 AWS 章节与现有部署步骤衔接顺畅
