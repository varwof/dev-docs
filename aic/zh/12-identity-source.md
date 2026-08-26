# AIC × LDAP/AD Identity Source Integration Specification

> 状态：🔶 部分落地（2026-08-24）：`bridge-ldap`（`github.com/varwof/bridge-ldap`）+ `bridge-oauth`（`github.com/varwof/bridge-oauth`）均已实现，core `identity-user` profile 经 `IdentitySource` 接口消费
> **FUTURE**：LDAP provisioner（§3.3 P1）、目录同步（§3.4 P2）、group→role 映射（§3.1 P0）、状态→自动吊销（§3.2 P0）
> 日期：2026-08-01（更新 2026-08-24）
> 定位：把 LDAP/AD 从"签发时查目录"提升为**一等身份来源**，与 AIC/IAM + SPIFFE + OAuth 组成完整身份体系。
> 关联：`11-spiffe-oauth.md`（SPIFFE/OAuth 互操作）

## 0. 一句话

LDAP/AD 市场存量巨大（企业目录事实标准），它是**身份来源**，不是竞争者。AIC/SPIFFE/OAuth
负责"身份如何表达和验证"（管道），LDAP/AD 负责"身份从哪来、谁是谁、属于哪个组"（数据源）。
两者是**数据源 × 身份形态**的互补，不是二选一。

## 1. 三层身份架构：来源 → 身份 → 形态

```
                 ┌─────────────────────────────────────┐
                 │   身份来源（Source of Truth）         │
                 │   LDAP / AD / FreeIPA（企业目录）      │
                 │   人 · 组 · 属性 · 启用状态 · 部门 OU   │
                 └──────────────────┬──────────────────┘
                                    │ ① 目录同步 / 成员查询 / 状态
                                    ▼
                 ┌─────────────────────────────────────┐
                 │   统一身份（Identity）                │
                 │   PrincipalUid · AgentId · 组 → 角色  │
                 │   （AIC 的核心身份概念）               │
                 └──────────────────┬──────────────────┘
                                    │ ② 签发 / 投影
                                    ▼
        ┌───────────────┬───────────────┬───────────────┐
        ▼               ▼               ▼               ▼
   X.509 视图      JWT 视图       策略视图        审计视图
   AIC 证书      SPIFFE JWT-SVID  RBAC/authorize  Merkle 链
                + RFC 9068       (12 规范)       统一 sub
```

**关键洞察**：LDAP/AD 与 OAuth/OIDC 决定"你是谁"（身份来源），AIC/SPIFFE/OAuth 决定"怎么证明"（身份形态）。
两者职责不重叠。LDAP/AD 不是被替代，而是成为整套体系的数据底座。

## 2. 现状盘点

| 组件 | 现状 | 角色 |
|---|---|---|
| `core/internal/ca/ldap.go` | 签发时 `LookupLDAP` 查目录 → 填充证书 subject（CN/O 等） | 来源 → 证书字段 |
| `core/internal/ca/ldap.go` | `CheckMembership`（memberOf 组检查） | 来源 → 组 → 角色 |
| `bridge-ldap` 卫星（`github.com/varwof/bridge-ldap`） | 独立 HTTP API：`/api/v1/lookup`、`/api/v1/check-membership`、`/api/v1/backends`；多后端（AD/OpenLDAP）+ 热重载 | 远程目录访问（网络隔离场景） |
| provisioner 架构 | mTLS / token / OIDC 三种认证 | 认证方式扩展点（新增 LDAP provisioner 即可） |

**结论**：查询/成员检查/多后端/热重载**全部已有**。缺的是把 LDAP/AD 接进**身份来源管线**
（组→角色映射、状态→吊销、认证→换 JWT）——这四件事目前是断的。

## 3. 补齐的四条身份来源管线

### 3.1 组 → 角色映射（授权来源）

企业目录的组（memberOf）天然是 RBAC 角色来源。映射表：`组 DN → 核心角色`。

```
LDAP 组（memberOf）          核心角色
─────────────────────────────────────
CN=PKI-Admins,OU=IT        → admin
CN=PKI-Operators,OU=IT     → ops
CN=Cert-Users,OU=All       → user
```

- 映射配置放 `authz.json`（与现有角色策略同源，新增 `ou_to_role` 或 `group_to_role` 段）
- AIC 签发时：查用户 memberOf → 映射角色 → 派生 `PrincipalAuthorization.grants` /
  capabilities（已有 `ProfileAgentProxy` 从 policy 派生的逻辑可复用）
- gateway 侧同理：`RunAccessPipeline` RBAC 用组映射（已有 `policy.HasAnyGrant`）

### 3.2 状态 → 吊销（生命周期）

**目录状态是证书生命周期的输入**：

- AD `userAccountControl` 位（禁用/锁定）→ 触发吊销
- 用户从目录删除 → 吊销其全部 AIC 证书（已有 `RevokeByPrincipalUid` SQL 快路径，<10ms）
- 离职检测 = 目录中无此用户 or 禁用 → `revoke-by-principal`

**实现**：目录同步任务（周期轮询 or webhook）比对目录状态与证书表 `principal_uid`/`agent_id`
（DB migration v22 已存），状态变化 → 自动吊销 + 审计日志。

### 3.3 认证 → 换统一 JWT（LDAP provisioner）

新增第 4 个 provisioner（LDAP）：

- 用户名 + 密码 → 目录 bind 验证 → 查 memberOf/属性 → 组→角色 → 返回 `AuthResult`
- 复用 `Registry.Authenticate()` 统一认证入口，与 mTLS/token/OIDC 并列
- 产物：统一 JWT（`11` 规范）+ `/api/v1/session`（Web 登录场景，浏览器不持证书）
- 价值：**Web 用户登录从"只能靠证书"扩展到"目录账号密码"**，覆盖企业存量用户习惯

### 3.4 目录同步（可选，替代 SCIM）

轻量目录同步：LDAP → 核心 DB（用户/组/状态），作为 SCIM 的轻替代。

- 周期全量比对 or 增量（`uSNChanged`/`modifyTimestamp`）
- 产出：角色变化 → 重签 AIC / 吊销旧证书；离职 → 吊销
- 复用 `bridge-ldap` 卫星（`github.com/varwof/bridge-ldap`，已有 backends 管理 + 热重载）

## 4. 认证方式矩阵（扩展后）

| Provisioner | 认证凭据 | 适用场景 | 身份产物 |
|---|---|---|---|
| mTLS | AIC 证书 | 原生 App / 服务端 | X.509 + AIC |
| B2 透传 | 网关 `X-Client-Cert-DER` | 服务端经网关 | 证书 → AuthUser |
| Token | API token | 脚本 / CI | AuthResult |
| OIDC | 第三方 IdP JWT | 外部登录（Google/GitHub） | 用户身份 |
| **LDAP（新增）** | 目录账号 + 密码 | **企业 Web 登录（存量最大）** | 组→角色 → JWT |

> 所有认证方式**统一走 `Registry` → 同一套 RBAC + 审计 + Merkle 管线**，新增 LDAP 不破坏
> 现有安全模型（fail-closed、证书仍是最强身份锚）。

## 5. 与 11/12 规范的衔接

- **11 转换矩阵补充**：`LDAP/AD 用户 → AIC/JWT` = LDAP bind + 组→角色 → 统一 JWT（新增一行）
- **12 授权模型补充**：`subject` 可来自目录（`memberOf` 组集）；`/authorize` 决策链的 RBAC
  层可直接消费目录组映射
- **11 缺口清单更新**："目录生命周期"从"SCIM 补件"改为"**内建：LDAP 同步 + 状态→吊销**"
- **04 示例**：LDAP 用户经目录登录 → JWT → `/authorize` 决策（Web 全链路）

## 6. 覆盖提升

| 身份来源维度 | 之前 | 内建后 |
|---|---|---|
| 目录存量接入 | 仅签发时查字段 | 一等身份来源（组/状态/认证全管线） |
| 企业 Web 登录 | 仅证书 | 目录账号密码 + JWT |
| 离职/禁用处理 | 手工吊销 | 目录状态 → 自动吊销 |
| 组 → 角色 | 无映射 | memberOf → RBAC 角色 |
| 目录生命周期 | 建议 SCIM | 内建目录同步（SCIM 可选） |

## 7. 落地路径

- **P0**：组→角色映射（authz.json 扩展）+ 状态→吊销任务（复用 `RevokeByPrincipalUid`）
- **P1**：LDAP provisioner（bind 认证 + memberOf → AuthResult → 统一 JWT）
- **P2**：目录同步（增量同步 + 角色变更重签）+ `/authorize` 消费目录组集

## 8. 待决策点

1. **组→角色映射放哪**：authz.json 扩展（推荐，同源）vs 独立 `ldap_roles.json`
2. **认证绑定**：LDAP provisioner 是否强制"目录存在该用户"（推荐：是，防幽灵账号）
3. **状态同步触发**：周期轮询（简单）vs webhook/AD event（实时，复杂）
4. **吊销策略**：目录禁用即吊销（严格，推荐）vs 仅标记待复核
