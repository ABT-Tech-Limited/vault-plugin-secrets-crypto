# 设计：setup-ha.sh 新增 gen-backup-token（API 生成最小权限备份 token）

- **日期**：2026-07-06
- **分支**：`feat/gen-backup-token`（建议）
- **状态**：已澄清，待 review

## 1. 背景

[DEPLOY_HA.md](../../../deploy_ha/DEPLOY_HA.md) 的「自动备份」小节（L400-419）教用户用 `vault` CLI 创建最小权限备份 token：

```bash
vault policy write raft-snapshot - <<'EOF'
path "sys/storage/raft/snapshot" { capabilities = ["read"] }
EOF
vault token create -policy=raft-snapshot -period=720h -orphan
```

但部署机通常**未安装 vault CLI**，这两步无法执行，自动备份就卡在「没有安全 token」——只能退回用 root token，违背最小权限原则。

**本次目标**：新增 `./setup-ha.sh gen-backup-token`，用 HTTP API（复用脚本内 `curl_vault`）复刻上面两步，产出可直接用于 crontab 的最小权限、可续期 token；并把文档「自动备份」小节改以该命令为主路径。

**范围（用户已确认）**：**仅生成 token**。不写 cron、不做旧快照轮转清理、不改 `backup` 命令（[cmd_backup](../../../deploy_ha/setup-ha.sh) 已支持 `VAULT_TOKEN` 环境变量做非交互备份）。

## 2. 确定的约束（来自需求澄清）

| 维度 | 决定 |
|------|------|
| 命令归属 | `setup-ha.sh` 新增子命令 `gen-backup-token`（不新建 `deploy.sh`） |
| 依赖 | 纯 HTTP API（复用 `curl_vault`），**不依赖 vault CLI** |
| policy 名 | `raft-snapshot`（沿用既有文档约定） |
| token 生命周期 | **periodic**，`period=720h`（沿用既有；用户选「可续期」） |
| orphan | 是，`no_parent=true`（沿用既有 `-orphan`） |
| 权限收紧 | `no_default_policy=true` + policy 显式含 `renew-self`（见 §4） |
| token 输出 | 终端打印 + 写入 `backups/backup.token`（`chmod 600`） |
| root token 来源 | 优先 `$VAULT_TOKEN`，否则交互输入（`read -r -s`，同 `register-plugin`） |

## 3. 命令行为（`cmd_gen_backup_token`）

1. `addr=$(vault_addr)`；取 root token（优先 `$VAULT_TOKEN`，否则交互输入）。为空则报错退出。
2. **写 policy**（`PUT /v1/sys/policies/acl/raft-snapshot`），body 的 `policy` 字段为两条：
   ```hcl
   path "sys/storage/raft/snapshot" { capabilities = ["read"] }
   path "auth/token/renew-self"     { capabilities = ["update"] }
   ```
   用 `-o /dev/null -w "%{http_code}"` 判定（期望 `204`/`200`）；非期望值报错退出。
3. **创建 token**（`POST /v1/auth/token/create`），body：
   ```json
   {"policies":["raft-snapshot"],"period":"720h","no_parent":true,
    "no_default_policy":true,"display_name":"raft-snapshot-backup",
    "meta":{"purpose":"automated-raft-snapshot-backup"}}
   ```
4. 解析 `.auth.client_token`（`python3`，同脚本既有惯例）。为空或响应含 `errors` → 报错退出并打印响应。
5. **输出**：打印 token；`mkdir -p backups` 后写入 `backups/backup.token` 并 `chmod 600`。
6. 打印后续用法提示（crontab 一行）。

## 4. 关键决策：最小权限 policy（为何多加 `renew-self`）

- 备份本身只需 `read sys/storage/raft/snapshot`（`seal-status` 是免认证端点，无需权限）。
- 但 **periodic token 要长期不过期，必须能被续期**；续期端点 `auth/token/renew-self` 需要 `update` 能力。
- 若保留 default policy 可间接获得 `renew-self`，但 default policy 还附带 cubbyhole / lookup-self 等冗余能力。
- **决策**：`no_default_policy=true` + policy 显式授予「snapshot read」与「renew-self」两条 → 该 token 只能做两件事：**读快照、续自己**。这是真正的最小集。
- 同步把 DEPLOY_HA.md 的 policy 片段从一条更新为两条，保持文档与实现一致。

## 5. 文档改动（DEPLOY_HA.md「自动备份」L400-419 改写）

- 主路径改为 `./setup-ha.sh gen-backup-token`（无需 vault CLI），并说明它等价于原来的两条 `vault` 命令。
- policy 片段更新为两条（snapshot read + renew-self）。
- crontab 示例改为**含续期**（periodic token 需定期 renew；续期失败不应阻断当次备份）：
  ```bash
  # 每天 02:00：先尽力续期备份 token，再备份（HTTPS + 自建 CA）
  0 2 * * * cd /path/to/deploy_ha && T=$(cat backups/backup.token) \
    && { curl -s --cacert tls/ca.pem -H "X-Vault-Token: $T" -X POST \
         https://127.0.0.1:8200/v1/auth/token/renew-self -o /dev/null || true; } \
    && VAULT_TOKEN=$T ./setup-ha.sh backup >> logs/backup.log 2>&1
  ```
  （`TLS_DISABLE=true` 时改 `http://` 并去掉 `--cacert`，文档给注记）
- 保留「若已装 vault CLI」的原生方式作为一句话备选。
- `help` 文本 Operations 段增加 `gen-backup-token` 一行。

## 6. 不做的事（范围边界 / YAGNI）

- ❌ 不写 cron / 不做快照轮转清理（用户自行接）
- ❌ 不改 `backup` 命令（已支持 `VAULT_TOKEN`）
- ❌ 不做 token 自动续期守护进程（靠 cron 里那一步 `renew-self`）
- ❌ 不新建 `deploy.sh`、不改其它子命令

## 7. 验收 & 验证

- [ ] `bash -n setup-ha.sh` 通过
- [ ] 隔离测试（stub `curl_vault`）断言：(a) policy body 含两条 capability；(b) token-create body 含 `period=720h`/`no_parent`/`no_default_policy`；(c) 能从 mock 响应提取 `client_token`；(d) `errors` 响应走失败分支并非零退出
- [ ] e2e（需真实集群，用户执行）：`gen-backup-token` → `VAULT_TOKEN=<token> ./setup-ha.sh backup` 成功 → 用该 token 访问越权路径（如 `GET sys/mounts`）返回 `403` → `renew-self` 返回 `200`
- [ ] DEPLOY_HA.md「自动备份」小节改为 API 主路径 + 两条 policy + 含续期的 crontab
- [ ] `help` 输出含 `gen-backup-token`
