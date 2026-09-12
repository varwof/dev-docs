# 15 AIC 端到端运行手册（core → PKI → 用户证书 → AIC 签发 → 消费）

> 状态：2026-09-12 依据当前工作区代码核对，**尚未在真机跑通全链路**。
> 本文记录每一步的**真实入口**（命令 / 接口 / 字段），并标出当前不可执行的位置。

标记约定：✅ 代码里已确认存在 · ⚠️ 存在但需人工步骤或参数待确认 · ❌ 当前缺失

## 0. 全景

```
                 ┌─────────────── core（CA + API :4433）───────────────┐
                 │  root → 8 个 sub-CA（management/tls/people/…）      │
                 └───────┬───────────────────────────────▲─────────────┘
                         │ ①签发用户证书                  │ ④CSR + DA evidence → 签发 AIC
                         ▼                               │
                   用户证书（people CA）             aic-agent
                         │                               │
                         │ ②用用户私钥签 DA TBS          ③申请 / 轮询
                         ▼                               ▼
                    user-signer  ◀── 人工审批 ── console
                         │
                         └─④返回 DA evidence

   aic-agent ──⑤持 AIC 证书 / AIC-JWT──▶ aic-verifier 保护的服务
```

## 步骤 1：部署 core ✅

```bash
cd core
go build -o varwof-pki ./cmd/pki

# 生成样例配置（打印到 stdout，重定向即可）
./varwof-pki init-config > core.json

# 起服务（默认 TLS :4433；配置项 serve.tls_addr / tls_cert / tls_key / db / cas.<name>）
./varwof-pki serve -config core.json
```

要点：`init-config` 只是**打印样例**，默认用户名 `admin`、密码 `changeme`，TLS 证书路径
`/etc/varwof/core/keys/server.pem`，生产环境必须改。数据库走 `cfg.DB`（serve 启动时 `db.Open`）。

## 步骤 2：创建 PKI 体系 ✅

```bash
./varwof-pki init-full \
  -out-dir ./pki \
  -root "Varwof Root" \
  -org "Varwof" \
  -hierarchy simple        # simple(3 层) | enterprise(4 层)
```

`init-full` 一次性创建 root 和 8 个 sub-CA，并自动签发服务证书：

| sub-CA | 用途 |
|---|---|
| `management` | 管理类客户端证书（admin / operator / auditor / readonly） |
| `tls` | TLS / OCSP / 网关服务证书 |
| **`people`** | **人类客户端证书 + AIC agent 证书（本流程用这个）** |
| `codesign` | 代码签名（RSA-4096） |
| `tsa` | 时间戳签名（RSA-4096） |
| `hr` / `vpn` / `acme` | 部门证书 / VPN 客户端 / ACME-SCEP 自动注册 |

其他参数：`-default-key-type`（默认 `ecdsa-p384`）、`-root-validity`（默认 7300 天）、
`-encrypt-keys`（加密根私钥）、`-import-root-cert`（用已有根，跳过根创建）。
层次结构细节见 `dev-docs/core/zh/pki-hierarchy.md`、`pki-architecture.md`。

## 步骤 3：用 client 创建用户证书 ✅ / ⚠️

```bash
cd client
go build -o varwof-cli .

cat > cli.json <<'EOF'
{
  "server":      "https://127.0.0.1:4433",
  "ca_cert":     "../core/pki/root/ca.pem",
  "client_cert": "../core/pki/management/superadmin.pem",
  "client_key":  "../core/pki/management/superadmin-key.pem"
}
EOF

./varwof-cli --config cli.json cas          # 先确认能连上、能列 CA
./varwof-cli --config cli.json issue --cn alice --profile <用户证书 profile>
```

client 通过 **mTLS** 直连 core API，用管理证书鉴权。可用子命令：`issue` / `revoke` /
`renew` / `list` / `cas` / `find-by-key`；AIC 相关的是 `aic issue|batch|list|jwt`。

⚠️ **待确认**：人类用户证书应该用哪个 `--profile` 值。代码里 `Policy.ProfileRoles(profile)`
做映射，但「人」的 profile 名没有写在文档里；已确认存在的是 `tls-server`（服务证书）和
`agent-proxy`（AIC 证书）。

## 步骤 4：签发 AIC 证书（agent → user-signer → core）⚠️

这是整条链路里手工成分最重的一步。

### 4.1 agent 侧构造并签署 DA TBS ✅

`DelegationAuthTBS`（`types`）字段：`version` / `agent_id` / `principal_uid` /
`reason`（reason_code + description）/ `capabilities` / `delegation_mode` /
`requested_lifetime` / `timestamp` / `nonce`。

- `principal_uid` = `varwof:<cn>:<base64url(sha256(SPKI))>`，取的是**用户证书**的 SPKI 摘要；
- 用**用户私钥**对 `DER(DelegationAuthTBS)` 做 ECDSA-SHA256 签名。

权威参考实现：`core/bench/scenario.go` 的 `buildAICBody`（注释声明它与生产 C3 流程逐字节一致）。

### 4.2 提交 user-signer 申请 ✅

user-signer 的 AIC 端点（`internal/server/routes_aic.go`）：

```
POST /v1/aic/requests                     提交申请（mTLS agent 身份）
GET  /v1/aic/requests                     列出待审（console）
GET  /v1/aic/requests/{id}                详情
PUT  /v1/aic/requests/{id}/capabilities   console 修改能力范围
POST /v1/aic/requests/{id}/approve        批准：签 DA + 返回 evidence
POST /v1/aic/requests/{id}/reject         拒绝
```

批准后返回 `{ da, user_cert_pem }`，这就是拿去 core 换证书的 evidence。

### 4.3 提交 core 签发 AIC 证书 ✅

**接口是 `POST /api/v1/certs`**（路径归一化后落到 `/certs`），`profile` 用 `agent-proxy`。

请求体字段（取自 `bench/scenario.go` 的生产同构实现）：

```json
{
  "ca": "people",
  "cn": "<agent_id>",
  "profile": "agent-proxy",
  "subject": "/CN=<agent_id>/OU=...",
  "validity": 1,
  "agent_id": "<agent_id>",
  "principal_uid": "varwof:<cn>:<base64url(sha256(SPKI))>",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----",
  "user_auth_signature": "<base64 ECDSA-SHA256 over DER(DA TBS)>",
  "user_auth_signature_algo": "ECDSA-SHA256",
  "user_auth_nonce": "<base64>",
  "user_auth_lifetime": 3600,
  "user_auth_timestamp": "<RFC3339>",
  "user_auth_reason_code": "API_ISSUE",
  "user_auth_reason_description": "..."
}
```

core 校验 DA 签名、以及 `principal_uid.keyHash` 是否等于用户证书的 SPKI 摘要，然后签发。
`csr_pem` 模式表示私钥在客户端生成，core 不接触私钥。

## 步骤 5：消费 AIC 证书 ✅

**mTLS 载体**：把签出的 AIC 证书和 agent 私钥配给调用方（`aic-agent` 的 `CertFile` /
`KeyFile`），服务端 `aic-verifier` 用 `CACertFile`（people CA）验链。

**Bearer 载体**：用 `varwof-cli aic jwt` 把 x509 AIC 换成 AIC-JWT（RFC 8693），或由 agent
用本地密钥自铸（此时服务端 `JWTCAFile` 必须信任该密钥 / CA）。

服务端接入两种形态：

- 反向代理：`aicverifier.NewServer(conf, []Route{{Path, Target, RequiredCapabilities}})`
- 嵌进现有 HTTP 服务：`conf.Handler(next)`，业务里 `aicverifier.FromContext(ctx)`

---

# 实测记录（2026-09-12，本机单机部署）

目标机无既有 varwof 安装（只有无关的 `syncthing@varwof`），有免密 sudo。

## 实际执行的命令

```bash
# 1) 构建并安装
cd core && go build -o /tmp/varwof-pki ./cmd/pki
sudo install -m 0755 /tmp/varwof-pki /usr/local/bin/varwof-pki     # varwof 0.4.0+dirty

# 2) 建 PKI（同时生成 pki.json / authz.json / 初始 CRL）
sudo mkdir -p /etc/varwof/core && sudo chown -R varwof:varwof /etc/varwof
varwof-pki init-full --out-dir /etc/varwof/core \
  --root "Varwof Root CA" --org Varwof --domain localhost --hierarchy simple

# 3) 装并启动 systemd 服务
sudo systemctl daemon-reload && sudo systemctl enable --now varwof-core
```

生成后对 `pki.json` 的手工修正：

| 键 | 生成值 | 改成 | 原因 |
|---|---|---|---|
| `serve.addr` | `:443` | `:8443` | 443 是特权端口；服务以 `varwof` 用户运行 |
| `serve.tls_addr` | 缺失 | `:4433` | 生成配置**根本没开 HTTPS 监听** |
| `serve.tls_client_ca` | 缺失 | Management CA | 否则 mTLS 不校验客户端证书 |
| `serve.tls_cert` | `api.pem` | `api-chain.pem` | `api.pem` 只有叶子证，只信根的客户端拼不出链 |
| `capability_schemes` | 缺失 | 部署内 data 副本 | 内嵌 scheme 已移除，不配就禁用注册校验 |

systemd 单元 `/etc/systemd/system/varwof-core.service`：`User=varwof`、
`NoNewPrivileges=true`、`ProtectSystem=full` + `ReadWritePaths=/etc/varwof/core`。

## 验收结果

- `varwof-core` enabled + active；监听 `:8443`(HTTP) / `:4433`(mTLS) / `:8081`(CRL 静态)
- `GET http://127.0.0.1:8443/healthz` → `{"status":"ok","db":"ok","tsa_signer":"ok","ocsp_signer":"ok","crl_status":"ok"}`
- `curl --cert superadmin.pem --key superadmin.key https://localhost:4433/api/v1/cas` → 9 个 CA
- `varwof-cli <config.json> cas` → 列出 9 个 CA（mTLS 管理通道打通）
- 部署目录 1.0M，20 个 `.pem` / 19 个 `.key`

## 实测中踩到的坑（与缺口清单呼应）

1. **`serve --install` 在 Linux 上不可用** —— `cmd/pki/serve_unix.go` 直接返回
   "service installation is only supported on Windows"，Linux 的 systemd 单元必须手写。
2. **生成配置默认 `serve.addr :443` 且没有 `tls_addr`** —— 不调整要么需要 root 绑特权端口，
   要么根本不启 HTTPS。
3. **服务端证书不带中间 CA** —— `tls/api/certs/api.pem` 只有叶子证，只信根的客户端会报
   `x509: certificate signed by unknown authority`，需要自己拼 `api-chain.pem`（叶子 + TLS CA）。
4. **`capability_schemes` 必须配置** —— 不配则启动日志报 "capability schemes load failed,
   registration validation disabled"，这正是 G1 / G9 在 core 侧的体现。
5. **`varwof-cli` 用法与 README 不符** —— 实际是 `varwof-cli <config.json> <command>`
   （位置参数），README 写的是 `--config config.json`。
6. **CLI 强制配置文件权限 0600** —— 否则报 `Config error: ... is world-readable`。
7. `init-full` 期间对每个服务证书打印 `ca/sign: no issuance policy configured; CN/SAN
   restrictions are NOT enforced`（本次未影响签发，说明签发策略尚未启用）。

## 部门管理员与用户证书（已实测）

用 client 走通了「超管签部门管理员 → 管理员签本部门用户」的两级流程。

```bash
C=/etc/varwof/core

# 1) 超管为每个部门签发管理员证书（m-admin + CA scope 限定部门 CA）
varwof-cli superadmin.json issue --cn hr-admin \
  --ca "Varwof Management CA" --profile m-admin \
  --ca-scope "Varwof HR CA" --out $C/admins

# 2) 管理员用自己的证书签发本部门用户证书
varwof-cli $C/admins/hr-admin.json issue --cn hr-user01 \
  --ca "Varwof HR CA" --profile tls-client --out $C/users/hr
```

产物布局：管理员证书与私钥在 `/etc/varwof/core/admins/`，用户证书按部门在
`/etc/varwof/core/users/<dept>/`。client 的 `--out` 写的是 `<serial>.pem` /
`<serial>-key.pem`，按 CN 命名需要调用方自己重命名。

**实测结论**

- 管理员证书把 scope 写进 SAN URI：`urn:pki:ca:Varwof HR CA`；
- 用户证书由对应部门 CA 签发，链验证到根全部 OK；
- 越权阻止有效：hr-admin 从 People CA 签发 → `permission denied for this CA`；
- 提权阻止有效：hr-admin 试图自造 `m-admin` 证书 →
  `management sub-CA profile mint is reserved to superadmin`。

**注意**

- `develop` 部门没有现成 CA。这里用 `sub-ca create --name "Varwof Develop CA"
  --parent "Varwof Root CA"` 新建了一个，并手工加进 `core.json` 的 `cas` 表。
  业务 sub-CA **不会**写入 `ca_meta`，所以 `ca list` / `cas` 看不到它（签发本身
  走 `cfg.CAs`，不受影响）；
- `sub-ca create` 生成的证书 subject 是 `O=PKI Sub-CA`，与 init-full 建的部门 CA
  （`O=<组织名>`）不一致，属外观差异。

## AIC 签发实测：关键卡壳记录（2026-09-12）

打通 x509 这条路时依次撞上 8 道关卡，按**撞到的顺序**记录，避免下次重踩。

### 1. AIC 能力必须已注册，且用 scheme 限定式
`capregistry: invalid format: varwof-gateway-v1:gateway:read` —— core 现在用
`capability/data` 里迁移后的 id（`varwof/gateway-v1:admin:config`），而
`core/bench/scenario.go` 里写的 `varwof-gateway-v1:gateway:read`（连字符、无斜杠）
已不合法。**以注册表为准**。

### 2. agent-proxy profile 必须有 OU
`apply profile: agent-proxy profile requires at least one OU (OrganizationalUnit) for gateway RBAC`。
client 用 `--ou gateway:reader`。

### 3. PA 是 **OU 推导**出来的，会覆盖请求里带的 PA
`internal/ca/sign.go:480`：

> applyProfile may auto-derive PA from authz.json; here we re-validate that
> auto-derived PA covers the AIC capabilities.

所以**"在用户证书里写 PA"对 AIC 签发不起作用**——`--pa` 也会被覆盖。真正决定
PA 的是 OU → 角色 → 角色 grants。

### 4. OU 必须存在于 `authz.json` 的 `ou_mapping`
映射表里 gateway 的条目只有 `gateway:reader|writer|ops|ddl`。用
`--ou gateway:admin` 时**映射不到任何角色**，推导出空 PA，于是无论怎么加 grants
都报 "not covered"。这是我卡最久的一处。

### 5. PA 覆盖是**精确字符串匹配**
`validatePrincipalAuthForAIC`（`internal/ca/sign.go:1899`）用
`g.CapabilityId != cap.CapabilityId` 直接比字符串，**不支持通配**。所以
`gateway:*` 覆盖不了 `admin:config`；角色 grants 必须逐条列出与申请**完全相同**
的能力 id（scheme + capability_id 都要对）。

### 6. principal_uid 有**两种格式**，别混
| 场景 | 格式 |
|---|---|
| user-signer `POST /v1/aic/requests` | `realm:identifier`（两段；keyHash 由 mTLS 证书推导） |
| core `POST /api/v1/certs` | `realm:identifier:keyFingerprint`（三段，base64url(sha256(SPKI))） |

### 7. 超时三层，互不替代
| 参数 | 默认 | 管什么 |
|---|---|---|
| `aic_request_ttl`（user-signer） | 30m | 人工审批排队 |
| `serve.da_max_timestamp_skew`（core） | 1m | DA 签出后多久必须兑换 |
| `requested_lifetime`（DA 内） | 3600s | 会话时长 → 决定 AIC 有效期 |

另外 `user add` 之后原先必须重启服务（UserStore 启动时读盘），已改成按需加载 + `Reload()`。

### 8. 读公钥却要解密（已修）
`fileBackend.GetPublicKey` 不吃密码，导入的密钥不在内存缓存里就永远
"exists but is locked"。修法：落盘时多写一份**明文公钥侧车** `<id>.pub`，
`GetPublicKey` 直接读它（公钥本非秘密），并在首次解密成功时自愈补写。

### 已知可用的 golden path（client 路径，已实测签出）

```bash
varwof-cli <cfg> aic issue \
  --user-cert <user>.pem --user-key <user>-key.pem \
  --agent agent-cli-01 --ou 'gateway:reader' \
  --caps 'varwof/demo-mysql-v1:SELECT:*' \
  --ca "Varwof People CA" --out /tmp/aic-cli
```

产出：AIC 扩展 version=1、agent_id、PrincipalUid、DelegationMode、Capabilities、
DA(lifetime/nonce/ts) 齐全，PA grants 与能力一致，EKU=ClientAuth，有效期 1 天。

### 仍然未解：user-signer 路径的 DA 验签

client 路径能过 core 的验签，说明**同一个 `DelegationAuthTBS` 结构本身没问题**；
user-signer 路径仍报 `api.delegation_signature_invalid`（v1/v2 都失败）。已排除：
密钥不匹配（三处公钥哈希一致）、DA 版本（v1/v2 正确产出）。已修一处真实差异：
`principalUidOf` 未设 `HashAlgo`（core 重建时设了 SHA-256，且 types 的 v1 golden
DER 里带这个字段）。**下一步**：在两侧 `asn1.Marshal(tbs)` 后各打一行 hex 日志对比，
一次定位剩余字段差异。

## AIC 签发最终可复现配方（2026-09-12 实测通过）

`/api/v1/certs` 现在支持 `csr_pem`，v1/v2 两条路都已在实机签出并核验。

### 前置（一次性）

| 条件 | 说明 |
|---|---|
| 能力已注册 | 用 scheme 限定式（如 `varwof/demo-mysql-v1:SELECT:*`） |
| OU 在 `ou_mapping` 里 | 如 `gateway:reader`；映射不到角色 → PA 为空 → 必拒 |
| 角色 grants 精确包含该能力 | 是字符串全等，不支持通配 |
| 用户证书带 PA 或可被 derive | 同上，derive 会覆盖请求里的 PA |

### 两步调用

```bash
# 1) 提交申请给 user-signer（agent_spki 决定 DA v1 还是 v2）
curl -sS --cert <user>-chain.pem --key <user>-key.pem -X POST \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"a1","principal_uid":"<realm>:<id>",
       "capabilities":[{"scheme_id":"varwof/demo-mysql-v1","capability_id":"SELECT:*"}],
       "reason_code":"API_ISSUE","description":"...","lifetime_sec":3600,
       "agent_spki":"<base64 SPKI DER>"}'          # ← 带它=DA v2；不带=DA v1
  https://localhost:8444/v1/aic/requests

# 2) 人工批准（key_password 放 body，不要只依赖会话解锁）
curl -sS --cert <user>-chain.pem --key <user>-key.pem -X POST \
  -H 'Content-Type: application/json' \
  -d '{"key_alias":"default","key_password":"<key pass>"}'
  https://localhost:8444/v1/aic/requests/<id>/approve

# 3) 拿 evidence 去 core 换证书（CSR 由 agent 本地生成，私钥不离开）
#    principal_uid 这里是三段式；signature_algo 用 evidence 里的原值
curl -sS --cert superadmin.pem --key superadmin.key -X POST \
  -H 'Content-Type: application/json' \
  -d '{"ca":"Varwof People CA","cn":"a1","profile":"agent-proxy",
       "subject":"/CN=a1/OU=gateway:reader","principal_uid":"<realm>:<id>:<keyfp>",
       "csr_pem":"<PKCS#10>","user_cert_pem":"<evidence 里的>",
       "capabilities":[...],
       "user_auth_signature":"<da.signature_value>",
       "user_auth_signature_algo":"ecdsa-with-SHA256",   /* ← 用 evidence 原值 */
       "user_auth_nonce":"<da.nonce>","user_auth_lifetime":<da.requested_lifetime>,
       "user_auth_timestamp":"<RFC3339 UTC>",
       "user_auth_reason_code":"<da.reason_code>",
       "user_auth_reason_description":"<da.reason_description>"}'
  https://localhost:4433/api/v1/certs
```

**核验要点**：证书公钥 == 我方 CSR 私钥的公钥；AIC 扩展（`.1.1`）存在；
链到根 OK；`key_pem` 为空（说明用了 CSR）。

## 调试技巧：TBS hex 对比（强烈推荐保留）

DA 验签失败时不要逐个字段排除——**在两侧 marshal 之后各打一行 hex**，一次定位：

- user-signer `internal/aic/sign.go`：`asn1.Marshal(tbs)` 之后打 `tbsDER`；
- core `internal/ca/delegation_auth_verify.go` 的 `verifyDASignature`：同位置镜像一行。

本次靠它一次揪出两个根因：

| 现象 | 根因 |
|---|---|
| signer 比 core **长 4 字节**，DER 里 `1813 "…+0800"` vs `180f "…Z"` | **TBS 时间戳必须 UTC**。本地时区 marshal 出 `+0800`（19 字节），core 从 RFC3339 `Z` 解析回来是 UTC（15 字节）。修法：`Timestamp: req.Timestamp.UTC()` |
| 长度相同，中间 32 字节不同，且 signer 段 == `sha256(SPKI)` | **agentKeyBinding 用错了密钥**：`/api/v1/certs` 当时不认 `csr_pem`，自己生成了密钥 |

## 本轮新增/变更的 API 面

| 端点 | 变更 |
|---|---|
| `POST /api/v1/certs` | **新增 `csr_pem` 支持**：有 CSR 就用其公钥签发、不回 `key_pem` |
| `POST /v1/aic/requests`（user-signer） | `agent_spki` 可选；带 → DA v2，不带 → DA v1 |
| `POST /v1/aic/requests/{id}/approve` | `key_password` 可放 body（step-up 时必须放） |

## 待办（下次收尾）

- [ ] **JWT 半边**：`varwof-cli aic jwt` 把 x509 换 AIC-JWT，或 agent 的 RFC 7523 兑换；
- [ ] **插桩降级**：`DA-TBS-HEX(signer)` / `DA-TBS-HEX(core)` 目前是 `slog.Info`，改成 `slog.Debug` 或删除；
- [ ] **接口文档**：`/api/v1/certs` 的 `csr_pem` 需补进 `core/docs/openapi.yaml`；
- [ ] **authz 模板**：实机 `/etc/varwof/core/authz.json` 已对齐，仓库模板 `core/auth/authz.json` 尚未同步；
- [ ] user-signer 的公钥侧车、`aic_request_ttl`、用户热加载等改动需补进它自己的 `docs/`。

---

# 缺口清单

以下为 2026-09-12 对 `aic-verifier` / `aic-agent` 两个 SDK 逐项核对的结果，按对闭环的影响排序。

| # | 环节 | 缺口 | 证据 |
|---|---|---|---|
| G1 | 加载能力规则数据 | **`aic-verifier` 没有任何 capability 数据加载器** | `Config.CapabilityRegistry` 只是接口；`register.Registry.ValidateCapability` 签名不匹配且无适配器；`gateway/capreg.Loader` 签名匹配但住在 gateway 仓 |
| G2 | 每请求授权裁决 | **CLC 没接进准入管道**，只有路由级 id glob，参数完全不参与 | `RunAccessPipeline` 仍调 `aicCapabilityMatches`；新增的 `AuthorizeCapabilities` / `AuthorizeOperation` 未被调用 |
| G3 | 裁决结果落地 | `AuthContext` 没有 verdict / reason / unresolved / effective grant，业务侧也没有门禁函数 | `AuthContext`（`aicverifier.go`）只有身份字段 |
| G4 | agent 取身份 | **`aic-agent` 没有 core 证书申请客户端**（CSR → 签发） | 全仓搜索无 `/cert/issue`、`/api/v1/certs`、CSR 相关代码 |
| G5 | 能力目录发现 | agent 不知道服务端注册了哪些 scheme / capability id | 无相关 API |
| G6 | 对接 core API | `UserCertResolver` / `CRLCache` / `OCSPCache` / JWT 信任根都只有接口或本地文件，没有 core HTTP 客户端 | `NewJWTVerifier(cas)` 只接受证书切片，没有 JWKS 拉取 |
| G7 | **（bug）** | TS agent 的 `issueAICCertificate` 打到 `${coreUrl}/cert/issue`，**core 没有这个路由** | core 路由是 `POST /api/v1/certs`（`internal/serve/api.go`）；`agent/src/aicRequest.ts` |
| G8 | 命名一致性 | core bench 用 `SchemeId: "varwof-gateway-v1"`（无 `/`，不合 CLC §3）；`capability/data/x-vendor/acme` 同样不合规 | `core/bench/scenario.go`；`capability/data/x-vendor/acme/v1.json` |
| G9 | scheme 验签 | capability scheme 的 PKCS#7 验签没有在 verifier 侧落地 | 只有 gateway 侧有 `capability_schemes_trust` 配置 |
| G10 | 人工审批 | user-signer 的 AIC 申请需要人工在 console 批准，没有自动化路径（可能是有意设计） | `routes_aic.go` 的 approve / reject 端点 |

## 另有两处参数待确认

- 人类用户证书的 `--profile` 取值（步骤 3）。
- `varwof-pki init-full` 产出的目录结构与 `client` 配置里证书路径的实际对应关系，
  需要跑一次实测确认。

## 最小闭环建议顺序

1. **G1 + G2 + G3**（verifier 侧）：加载能力规则 → 对具体操作裁决 → 结果写回 `AuthContext`
   并提供门禁函数。这三项完成，「Go 服务加载规则后验证客户端能否做某事」就成立。
2. **G4**（agent 侧）：补 core 证书申请客户端，把步骤 4 从手工变成代码。
3. **G6**：补用户证书 / CRL / OCSP / JWKS 的 core 客户端，去掉本地文件依赖。

其中 G2 需要先定两个策略：**操作参数从哪来**、**`allow_unresolved` 怎么处置**
（CLC §8.4 要求它不能当 allow）。
