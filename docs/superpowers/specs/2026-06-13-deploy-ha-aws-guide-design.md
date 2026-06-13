# 设计：deploy_ha AWS 单 AZ 3 节点部署指南完善

- **日期**：2026-06-13
- **分支**：`docs/aws-ha-deploy-guide`
- **状态**：已澄清，进入实现计划

## 1. 背景

`deploy_ha/` 是 Vault 加密钱包插件（v0.2.0）的 HA 集群部署套件，基于 Raft 整合存储 + TLS 双向认证，支持 Shamir 与 AWS KMS 两种解封方式。现在要把这套服务在 AWS 上集群化部署，但现有指南是泛化的「3 台 VM」描述，缺少 AWS 落地细节；同时检查中发现一处会导致部署失败的版本号 bug。

本次目标：**完善文档让 AWS 部署就绪 + 修复检查发现的小问题 + 一处必要的 gen-cert 证书 SAN 增强**，不重写工具链、不引入 IaC。

## 2. 确定的约束（来自需求澄清）

| 维度 | 决定 |
|------|------|
| 插件版本 | v0.2.0 |
| 解封方式 | Shamir（手动）；awskms 本轮忽略，仅留未来切换指引 |
| 节点数 | 3 节点 |
| 可用区 | **单 AZ**（3 台机器在同一个 AZ），非跨 AZ |
| 地址方案 | **直接用私网 IP**（非 Route53 DNS） |
| 客户端入口 | **客户端直连 3 个节点**（无 NLB），自行失败重试 |
| 基础设施交付 | 仅文档（手动建 EC2 / EBS / SG），不写 Terraform / CLI 脚本 |
| 工具改动 | 唯一例外：`gen-cert` 加 ~3 行支持把私网 IP 写入证书 SAN |
| 文档组织 | 方案 A：在现有 DEPLOY_HA.md 上叠加（不重写、不拆分） |

## 3. 检查 deploy_ha 的发现（本次处理范围）

| # | 问题 | 处理 |
|---|------|------|
| 1 | [.env.example](../../../deploy_ha/.env.example) 写 `PLUGIN_VERSION=v0.1.0`，但仓库是 v0.2.0、脚本与文档均按 v0.2.0 → 照抄会找不到插件二进制 | ✅ 修复：改为 v0.2.0 |
| 2 | 工具链硬编码 3 节点 | ⏸️ 不处理（本次就是 3 节点） |
| 3 | awskms 初始化用 `secret_shares` 而非 `recovery_shares`，可能报错 | ⏸️ 不处理（本轮忽略 awskms），文档注明 awskms 是未来项 |
| 4 | 指南缺 AWS 细节 | ✅ 新增 AWS 章节 |
| 5 | 解封文档只写 Shamir | ✅ 补一句声明本指南走 Shamir 路径 |
| 6 | crontab 明文 root token | ✅ 改为最小权限策略 token |
| 7 | 私网 IP 路径下 `gen-cert` 不会把 IP 写进证书 SAN（只放 `IP:127.0.0.1`）→ 节点间 + 客户端 TLS 校验失败 | ✅ 修复：gen-cert 加 `VAULT_SAN_IP` 支持 |

## 4. 节点数与可用性决策（写进文档）

### Raft Quorum 数学

| 节点数 | Quorum | 容忍故障 | 评价 |
|--------|--------|----------|------|
| 1 | 1 | 0 | 开发/测试，无 HA |
| 2 | 2 | 0 | ❌ 绝不用：故障面翻倍却零容错 |
| **3** | 2 | 1 | ✅ HA 最小生产基线 |
| 4 | 3 | 1 | ❌ 容错同 3，更贵更慢 |
| **5** | 3 | 2 | ✅ 关键业务 |

只能用奇数（1/3/5），永不用偶数。超过 5 台投票节点写入延迟上升，再扩用 performance standby。

### 单 AZ 3 节点的容错边界（本部署的取向）

- ✅ **扛得住**：单台实例故障（硬件 / 实例崩溃 / 重启）—— Raft quorum 2/3 仍满足
- ❌ **扛不住**：整个 AZ 故障（断电 / 网络隔离）—— 3 台一起失联

**AWS 原生缓解**：将 3 台 EC2 放进同一个 **spread placement group**，强制分散到不同底层硬件 / 机架（单 AZ 内每 group 上限 7 台），消除「三台共享一台宿主机」的相关性故障。这是单 AZ 下能做到的最好实例级隔离。

**升级路径**：要抵御 AZ 级故障，未来把 3 台分到 3 个 AZ 即可，架构 / 工具链无需改动，仅调整实例放置与子网。

## 5. 文件改动设计

改动 3 个文件：文档为主 + `.env.example` 修复与新增变量 + `gen-cert` 证书 SAN 增强。

### 5.1 `deploy_ha/setup-ha.sh`（gen-cert 增强，~3 行）

现状 [cmd_gen_cert](../../../deploy_ha/setup-ha.sh) 的 SAN 行：

```bash
local san="DNS:${fqdn},DNS:localhost,IP:127.0.0.1"
```

增强为：可选 `VAULT_SAN_IP` 时把私网 IP 追加为 IP SAN（向后兼容，未设置时行为不变）：

```bash
local san="DNS:${fqdn},DNS:localhost,IP:127.0.0.1"
if [ -n "${VAULT_SAN_IP:-}" ]; then
  san="${san},IP:${VAULT_SAN_IP}"
fi
```

> 说明：TLS 对 IP 地址的校验走 SAN 的 `iPAddress` 项，`DNS:<ip>` 不生效，因此必须以 `IP:` 形式写入。这是私网 IP 直连路径能跑通 TLS 的硬性前提。

### 5.2 `deploy_ha/.env.example`

```diff
- PLUGIN_VERSION=v0.1.0
+ PLUGIN_VERSION=v0.2.0
```

并在「This Node」段新增（带注释说明）：

```bash
# 本节点的私网 IP，写入证书 SAN（私网 IP 直连必填；用 DNS 名时可留空）
VAULT_SAN_IP=10.0.1.10
```

各节点 `.env` 差异对照表中补充 `VAULT_SAN_IP` 一行（每节点不同）。

### 5.3 `deploy_ha/DEPLOY_HA.md`

方案 A（叠加）下做如下改动：

**(a) 标题 / 前置条件微调**
- 标题由「（3 节点）」补充为「（AWS 单 AZ · 3 节点 · Shamir）」
- 前置条件表「服务器 3 台」补充 AWS 语境（3 台 EC2，同一 AZ，同一 spread placement group）

**(b) 新增「节点数怎么选」一节**（置于「架构概述」之后）
- 写入 §4 的 quorum 表
- 写入单 AZ 容错边界 + spread placement group + 升级到 3-AZ 的指引

**(c) 新增「AWS 单 AZ 部署」章节**（置于「部署流程」之前）
1. **网络与实例**：1 VPC + 1 私有子网（单 AZ）；3 台 EC2 同 AZ，放进同一 spread placement group；实例选型（内存敏感、`IPC_LOCK` / mlock、关 swap、建议规格下限）；装 Docker + Compose v2
2. **存储**：每台挂 gp3 EBS 作 `/vault/data`，开 EBS 静态加密；说明 Raft 每节点存全量
3. **安全组**（规则表）：`8200`（API，来自客户端 / 应用 SG）、`8201`（集群，安全组自引用，仅节点间）、`22` / SSM（仅堡垒机 / SSM）、出站按需
4. **地址与证书（私网 IP 路径）**：
   - 每台 `.env` 设 `VAULT_FQDN` 与 `VAULT_SAN_IP` 为该节点私网 IP；`VAULT_NODE_1/2/3_ADDR` 用 `https://<私网IP>:8200`
   - `gen-cert` 经 5.1 增强后把 `IP:<私网IP>` 写进 SAN，节点间 Raft TLS 与客户端 TLS 均可校验通过
   - 同一 VPC 内私网 IP 跨子网/同 AZ 直接可达
   - （备注一行：也可改用 Route53 私有 DNS，则无需 IP SAN；本指南按私网 IP）
5. **客户端访问（直连，无 NLB）**：
   - 客户端配置全部 3 个节点地址 `https://<私网IP>:8200`，CA 信任 `ca.pem`
   - 依赖 Vault standby 请求转发（默认开）：命中任意健康且已解封节点即可，写请求自动转发 leader
   - **无 LB，客户端需自行失败重试**：遇到 sealed（HTTP 503）/ 不可达节点要跳到下一个地址
   - 证书 SAN 已含私网 IP，客户端 TLS 直接通过
6. **AWS 版架构图**：新增一张，标注单 AZ + 3 实例 + spread placement group（不动原通用图）

**(d) 新增「Shamir 在 AWS 上的运维注意」**（并入 AWS 章节或「日常运维」）
- 每次重启 / 换实例 → 该节点需人工输 3 个 unseal key；给一段 break-glass 解封 runbook
- 不建议配 Auto Scaling Group（新实例起来是 sealed 需人工解封）；建议固定实例
- 留「将来切 KMS 自动解封」指引，指向 [vault-awskms-ha.hcl](../../../deploy_ha/vault-awskms-ha.hcl)
- Raft 快照建议 `aws s3 cp` 推 S3 + 生命周期策略

**(e) 小问题修复**
- crontab 明文 root token（备份小节）→ 改用最小权限策略 token，给出 policy 片段：
  ```hcl
  path "sys/storage/raft/snapshot" {
    capabilities = ["read"]
  }
  ```
- 解封步骤补一句：本指南走 Shamir 路径；awskms 自动解封为未来选项（init 拿到的是 recovery key），一句话带过

## 6. 不做的事（范围边界）

- ❌ 不写 Terraform / AWS CLI provisioning 脚本
- ❌ 不改 `setup-ha.sh` 的节点数逻辑（gen-cert SAN 是唯一改动，~3 行）
- ❌ 不展开 awskms 自动解封流程（仅留指引）
- ❌ 不引入 NLB（客户端直连）
- ❌ 不改插件代码、不改 docker-compose 结构
- ❌ 不做跨 AZ / 多区域内容（仅留升级指引）

## 7. 验收标准

- [ ] `.env.example` 的 `PLUGIN_VERSION` 为 `v0.2.0`，并含带注释的 `VAULT_SAN_IP`
- [ ] `setup-ha.sh` 的 `gen-cert` 在设置 `VAULT_SAN_IP` 时把 `IP:<私网IP>` 写入证书 SAN；未设置时行为不变
- [ ] DEPLOY_HA.md 含「节点数怎么选」节（quorum 表 + 单 AZ 容错说明）
- [ ] DEPLOY_HA.md 含「AWS 单 AZ 部署」章节：网络/实例（含 spread placement group）、EBS、安全组规则表、私网 IP 证书 SAN 说明、客户端直连与失败重试
- [ ] DEPLOY_HA.md 含 Shamir 在 AWS 的运维注意 + S3 快照建议
- [ ] crontab 备份示例改为最小权限策略 token，并给出 policy 片段
- [ ] 解封步骤注明本指南为 Shamir 路径
- [ ] 全文自洽：仅 Shamir / 3 节点 / 单 AZ / 私网 IP / 直连，无残留「3-AZ / 跨 AZ / NLB / Route53 为主」表述
