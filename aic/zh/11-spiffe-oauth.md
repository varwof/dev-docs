# AIC × SPIFFE × OAuth/OIDC Interoperability Specification

> 状态：🟢 核心 SPIFFE/AIC-JWT 已落地（2026-08-24 对齐实现）
> **FUTURE**：§4 OIDC 端点（`/api/v1/token`、`/.well-known/jwks.json`、`/.well-known/openid-configuration`）；L2 在线策略端点（`/api/v1/authorize`）
> 日期：2026-08-01（更新 2026-08-24）
> 定位：直接兼容，非桥接。AIC 身份同时是 SPIFFE SVID 与 OAuth/OIDC 主体，一套身份三个标准视图。
> 关联：`09-aic-iam-unification.md`（双形态身份总设计）
> 实现对齐：AIC-JWT（`draft-wei-aic-jwt-00`）已作为应用层 Profile 落地，
> claim 兼容映射见该草案 §18（AIC-JWT ↔ 统一 JWT Profile）。

## 0. 一句话

AIC 证书本身就是 X.509 证书，AIC 派生的 JWT 本身就能同时满足 **SPIFFE JWT-SVID**
与 **RFC 9068（OAuth 2.0 JWT access token）** 两种规范。因此不需要"桥接层"：
只需要约定 (a) AIC 证书携带 SPIFFE URI SAN、(b) 统一 JWT claim 映射、便能让 SPIFFE 与
OAuth 生态原生消费 AIC 身份。

## 1. 统一身份模型：一个 AIC，三种标准视图

```
                   ┌───────────────────────────┐
                   │     AIC（唯一身份源）        │
                   │  PrincipalUid · AgentId    │
                   │  Capabilities · Constraints │
                   └───────────┬───────────────┘
                               │
      ┌────────────────────────┼─────────────────────────┐
      ▼                        ▼                         ▼
  X.509 视图               JWT 视图（统一 Profile）      OIDC/OAuth 视图
  = SPIFFE X.509-SVID      = SPIFFE JWT-SVID           = RFC 9068 access token
  (spiffe:// URI SAN)      (sub=spiffe:// ID)          (iss/aud/scope/exp/jti)
                           + AIC claims                + AIC claims
```

**设计要点**：三者共享同一密码学身份（同一公钥/同一 CA/同一 JWKS 密钥），只是投影为
不同标准的格式。SPIFFE 验证方看 `sub=spiffe://...`，OAuth 资源服务器看 `scope`/`iss`，
AIC 应用看 `principal_uid`/`capabilities`——**同一份 JWT，互不冲突**。

## 2. 规范 A：AIC 证书 = SPIFFE X.509-SVID

### 2.1 URI SAN 约定

AIC 证书签发时 MUST 携带 SPIFFE ID URI SAN。SPIFFE ID 由证书身份派生：

```
Agent 身份：    spiffe://<trust-domain>/agent/<agentId>
Principal 身份：spiffe://<trust-domain>/principal/<principalUid>
```

- `<trust-domain>`：企业信任域（如 `varwof.com`），与核心的信任域配置一致
- 现有 `urn:pki:ca:<scope>` URI SAN 可共存（SPIFFE 允许额外 URI SAN）
- 证书的 AIC 扩展（`.1.1`）不变，SPIFFE ID 只是标准投影，**不需要新 OID**

### 2.2 与 SPIRE 集成

- 核心 CA 作为 SPIFFE trust bundle 的信任根：将核心 CA 证书注册到 SPIRE
  trust bundle（`spiffe://<td>` 的 bundle）
- SPIRE workload 用标准 SPIRE agent 验证 AIC 证书 = 验证 X.509-SVID
- 无需实现 SPIRE Workload API：企业已有 SPIRE 时直接消费；无 SPIRE 时 AIC 证书
  按 SPIFFE spec 可被任何 SPIFFE 兼容验证方解析

### 2.3 反向：SPIFFE X.509-SVID → AIC 语义

带 `spiffe://<td>/principal/<uid>` 或 `/agent/<id>` URI SAN 的证书，核心可解析映射为
AIC principal/agent（URI SAN → PrincipalUid）。若证书同时含 AIC 扩展则直接是 AIC。

## 3. 规范 B：统一 JWT Profile（同时是 JWT-SVID + OAuth access token）

### 3.1 Claim 映射表（AIC ↔ 标准）

| AIC 概念 | 统一 JWT claim | SPIFFE JWT-SVID 视图 | OAuth/RFC 9068 视图 |
|---|---|---|---|
| PrincipalUid | `principal_uid` | —（路径段） | — |
| AgentId | `agent_id` | 路径段 `/agent/<id>` | — |
| SPIFFE ID | `sub` | `sub` MUST = spiffe:// ID | `sub`（RFC 9068 不限格式） |
| Trust Domain | `iss`（保持 OAuth URL） | trust domain（由 `sub` + SPIFFE bundle 锚定，JWT-SVID 不读 iss） | `iss`（RFC 9068） |
| Capabilities | `scope` + `capabilities` | —（aud 可选） | `scope`（空格分隔） |
| 执行约束硬超时 | `exp` / `nbf` | `exp` | `exp` |
| 会话发起 | `iat` | `iat` | `iat` |
| 审计 / 防重放 | `jti` | — | `jti` |
| 委托模式 | `delegation_mode` | — | — |
| 资源范围 | `aud` | `aud`（MUST ≥1） | `aud` |

### 3.2 统一 JWT 示例

```json
{
  "iss": "spiffe://varwof.com",
  "sub": "spiffe://varwof.com/agent/agent-1",
  "aud": ["api://internal-service"],
  "exp": 1770000000,
  "iat": 1769996400,
  "nbf": 1769996400,
  "jti": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "scope": "ca:issue cert:revoke",
  "aic": {
    "capabilities": ["ca:issue", "cert:revoke"],
    "principal_uid": "varwof:alice:",
    "agent_id": "agent-1",
    "delegation_mode": "representative"
  }
}
```

> `capabilities`/`principal_uid`/`agent_id`/`delegation_mode` 嵌套在 `aic` claim 内（`types/aicjwt/claims.go` `AICClaims`），
> `scope` 在顶层（空格分隔字符串，RFC 9068 兼容）。

- **SPIFFE 验证方**：验 `sub`（spiffe://）+ `aud` + 签名（JWKS）→ JWT-SVID ✅
- **OAuth 资源服务器**：验 `iss`/`aud`/`scope`/`exp`/`jti` + 签名（JWKS）→ RFC 9068 ✅
- **AIC 应用**：读 `principal_uid`/`capabilities`/`delegation_mode` → 本地授权决策 ✅

> 同一签名密钥、同一 JWKS，三种消费方各取所需，无桥接转换。

## 4. 规范 C：OIDC/OAuth 端点（核心作为 IdP）—— **FUTURE（未实现）**

以下端点为设计目标，尚未在 core 中实现。当前 core 无 `/.well-known/*` 端点，
`/api/v1/token`（core）用于 OAuth password grant 上游消费（非 AIC→JWT 交换）。

| 端点 | 功能 | 兼容标准 | 状态 |
|---|---|---|---|
| `POST /api/v1/token` | AIC 证书（mTLS）→ 短期 JWT | client_credentials + mTLS client_auth | FUTURE |
| `GET /.well-known/jwks.json` | JWT 验签公钥集 | OIDC / JWT-SVID 共用 | FUTURE |
| `GET /.well-known/openid-configuration` | OIDC discovery | OIDC | FUTURE |
| `GET /.well-known/spiffe/...`（可选） | SPIFFE bundle 发布 | SPIFFE trust bundle | FUTURE |

### 4.1 签发流程

```
App（任意语言）
   │  mTLS（AIC 证书）或经网关 B2 透传
   ▼
POST /api/v1/token   grant_type=client_credentials
   ▼
核心：验证 AIC → 派生 SPIFFE ID → 计算 capabilities ∩ 策略
     → 签发统一 JWT（exp = min(证书有效期, ExecutionConstraints)）
   ▼
App 持有统一 JWT → 用 /jwks 验签 → 本地消费（SPIFFE / OAuth / AIC 任一视角）
```

### 4.2 OIDC 兼容

- `iss` 可同时发布为 OIDC issuer（`https://pki.varwof.com`）与 SPIFFE trust domain
  （`spiffe://varwof.com`）两套视图（见 §8 决策记录）
- 第三方 OAuth/OIDC 资源服务器直接用核心 JWKS 验证 token 即完成授权
- 反向：第三方 IdP 登录走现有 OIDC provisioner（第三方 JWT → 映射用户角色）

## 5. 转换矩阵（技术互转方法）

| 来源 | 目标 | 方法 | 是否需要新代码 |
|---|---|---|---|
| AIC 证书 | SPIFFE X.509-SVID | 签发时含 `spiffe://` URI SAN | 签发侧 + 配置 trust domain |
| AIC 证书 | SPIFFE JWT-SVID | `POST /api/v1/token`（mTLS）→ 统一 JWT | FUTURE（新端点 + JWKS） |
| AIC 证书 | OAuth access token | 同上（同一 JWT，RFC 9068 视图） | 复用 |
| SPIFFE X.509-SVID | AIC 语义 | URI SAN `spiffe://.../principal/<uid>` → PrincipalUid | 解析器 |
| SPIFFE JWT-SVID | AIC 委托 | 统一 JWT 即携带 AIC claims | 复用 |
| OAuth 第三方 token | AIC 用户身份 | OIDC provisioner（已存在）：第三方 JWT → 用户角色 | 已实现 |
| OAuth token | AIC 权限 | `scope`/`capabilities` 交集映射 | 映射函数 |
| Web App（无证书） | 统一 JWT | `POST /api/v1/token`（经网关 B2 或 `/session` 换取） | 复用 |
| LDAP/AD 用户 | AIC 证书 | 签发时查目录填 subject + memberOf → 角色 | 已部分实现 |
| LDAP/AD 用户 | 统一 JWT | LDAP provisioner：bind 认证 + 组→角色 → 统一 JWT（见 `13`） | 新 provisioner |
| LDAP/AD 状态 | 证书吊销 | 目录禁用/删除 → `RevokeByPrincipalUid` 自动吊销（见 `13`） | 同步任务 |

> 核心洞察：**JWT-SVID / OAuth access token / AIC-JWT 是同一份 JWT 的三个视角**，
> 所以多数转换是"同一份凭据换一种解析方式"，而非格式转换。

## 6. 覆盖边界分析（解决什么、不解决什么）

### 6.1 覆盖率评估

结论：**身份 ~95%，权限 ~80%，执行策略 ~75%**——三者解决的是**身份管道问题**
（你是谁、你能干什么、跨语言怎么执行），这是分布式系统里最硬的那 90%；其余是
**业务语义问题**，永远不该由身份框架承担。

### 6.2 三平面补集（非重叠竞争）

三者是三个不同平面的补集，而非竞争关系：

| 平面 | 负责 | 谁解决的问题 |
|---|---|---|
| OAuth/OIDC | **人**的身份 + 委托授权（bearer token、resource server） | Google/GitHub 登录、Web、三方 IdP |
| SPIFFE/SPIRE | **工作负载**的身份（动态编排里的 service-to-service） | K8s、微服务、容器 |
| AIC | **Agent** 身份 + 内嵌授权结果（X.509 扩展、离线自洽） | AI Agent、自有 PKI |

AIC 同时是两者的标准形态：**证书带 SPIFFE URI SAN = X.509-SVID，AIC→JWT =
JWT-SVID ∩ RFC 9068**。覆盖完整度来自"同一身份能进所有生态"，而非三套身份各管一摊。

### 6.3 诚实缺口清单（明确划出职责边界）

| 缺口 | 为什么三者不覆盖 | 补件 |
|---|---|---|
| 细粒度关系授权（文件夹/文档 ACL） | OAuth scope 粗、SPIFFE 不管业务授权 | FUTURE：细粒度授权 API |
| 属性级授权（IP/时间/设备上下文） | 身份框架只管身份 | **内建**：`/authorize` context 参数（见 `12`） |
| 业务策略语义 | 框架给管道，不给"规则内容" | **内建管道**：webhook 插件 + `/policies` 策略 API；语义由业务方定义（见 `12`） |
| 硬件/设备可信（TPM、DICE、机密计算 attestation） | 身份 ≠ 硬件证据 | TPM attestation、attestation 服务 |
| 数据加密与 KMS | 身份决定"谁"，不决定"数据用哪个密钥" | Vault/HSM、envelope encryption |
| 法律效力签名（eIDAS、国密合规） | 需要合规签名证书 | 独立签名证书体系（国密 OID 树可支撑） |
| 目录生命周期（入职/离职/组同步） | 认证 ≠ 目录同步 | **内建**：LDAP/AD 同步 + 状态→吊销 + 组→角色（见 `12-identity-source.md`）；SCIM 可选 |
| 领域策略**语义**（风控限额、ML 安全策略） | 框架给管道，不给"规则内容" | 业务侧策略引擎 |

执行策略那 75% 的余量，本质是：**管道（enforcement point）三者能全覆盖——网关、
应用内 JWT 本地决策、集中 authorize——但策略"内容"永远要业务方定义**。框架给管道，
领域给语义，两者都不越位。

## 7. 跨语言互通分析（七种主流语言）

### 7.1 互通结论

**能互通，而且这是本设计最顺的一点。** 互操作面收敛到两个 IETF 标准——JWT/JWKS +
X.509/mTLS——每个语言都有十年成熟库：

| 语言 | 验 JWT + JWKS | 消费 AIC claims |
|---|---|---|
| JavaScript/TypeScript | `jose`（node + 浏览器 `jose-webcrypto`） | ✅ 只读标准 JSON |
| Go | `golang-jwt/jwt` / `lestrrat-go/jwx` | ✅ |
| Python | `PyJWT` / `authlib` | ✅ |
| C/C++ | `jwt-cpp` / `libjwt` / OpenSSL 3.x | ✅（最辛苦但可行） |
| C#/.NET | `System.IdentityModel.Tokens.Jwt` | ✅ |
| Java | `Nimbus JOSE + JWT`（事实标准） | ✅ |
| Rust | `jsonwebtoken` crate | ✅ |

### 7.2 机理

AIC 的 ASN.1 语义只在**签发侧**解析一次、投影成 claims（`principal_uid`/
`capabilities`/`delegation_mode` 都是普通 JSON）；**消费侧永远只碰标准 JSON +
标准数字时间**。Java 不用懂 ASN.1，Rust 不用懂 AIC 扩展——语言互通由协议设计决定，
不是 SDK 决定（参考 SDK 只是薄封装）。

### 7.3 规范必须钉死的坑

| # | 坑 | 规范要求 |
|---|---|---|
| 1 | 算法混淆攻击 | 只签 `RS256/ES256/PS256`；禁 `RS1/RSA1.5`、禁 `alg=none` |
| 2 | JWK 格式差异 | RSA 用 `n/e`；EC 用 P-256/P-384 且 `crv` 一致（Java/C# 对 EC `x/y` 编码有差异） |
| 3 | 密钥轮换 | 必须发 `kid`，消费方按 `kid` 缓存并支持切换；测试覆盖轮换 |
| 4 | 类型定死 | NumericDate 秒级；`aud`/`scope` 的类型（string vs array）定死 |
| 5 | 浏览器拿不到 mTLS | Web 通道走 `/session` 换统一 JWT（统一 JWT 的原生用例） |
| 6 | C/C++ 无运行时生态 | 提供 Go 写的 `verify-jwt` CLI 兜底 + 参考实现 |

## 8. 决策记录（2026-08-01 已定稿）

| # | 决策点 | 结论 | 影响 |
|---|---|---|---|
| 1 | iss/sub issuer 视图 | **修订（2026-08-24，对齐草案 §18）**：`iss` 保持 OAuth/RFC 9068 URL；JWT-SVID 验证器不处理 `iss`，信任域由 `sub`（SPIFFE ID）+ 验证所用 SPIFFE bundle 锚定；`sub` 在 is_spiffe 模式下直接继承证书 agentId（即 SPIFFE ID） | RFC 9068 合规 + JWT-SVID 兼容（仅 typ 需投影） |
| 2 | sub 取值 | **sub = SPIFFE ID**（`spiffe://<td>/agent/<id>`）；`principal_uid`/`agent_id` 放自定义 claim | JWT-SVID 强要求满足，OIDC 不限制 sub 格式，双兼容 |
| 3 | JWT 有效期 | 与 `ExecutionConstraints` 硬超时对齐：`exp = min(证书剩余有效期, 约束硬超时, 会话 TTL)` | 短期、防重放 |
| 4 | token 端点授权范围 | **AIC mTLS + 网关 B2 透传 + /session 代表令牌** 三类通道均可签发 | 覆盖全部接入形态 |
| 5 | P1 参考实现语言 | **Go + Python + Node** 三语言 | 覆盖服务端 / AI Agent / Web 三生态 |
| 6 | 权限/策略执行内建 | **core 当 PDP，gateway 当 PEP**，两级授权（L1 本地 / L2 在线） | FUTURE：细粒度策略 API |
| 7 | 身份来源 | **LDAP/AD 作为一等身份来源**（组→角色 / 状态→吊销 / 目录认证→JWT / 目录同步），非 SCIM 补件 | 覆盖企业存量目录（见 `12-identity-source.md`） |

> 相关待定项（非阻塞，P2 阶段决定）：策略评估内嵌 vs 集中式（`09` 决策点 2）已由两级授权方案落地——**L1 内嵌 + L2 集中式并存，按敏感度分级**。

## 9. 与现有规范的关系

- **OID 树不变**：SPIFFE ID 走 URI SAN（标准字段），JWT profile 走外部格式，均不需要
  新 OID，符合 "Core is stable; semantics are extensible"
- **复用**：B2 证书透传（`X-Client-Cert-DER`）、`/api/v1/session`、OIDC provisioner
  的纯 stdlib JWT 验签（可扩展为签发）
- **v1.7 定稿不受影响**：本规范是互操作剖面，不修改 AIC 核心定义

## 10. 与 09 的关系

`09-aic-iam-unification.md` 定义"双形态身份 + 任意语言接入"总框架；本规范是其
**SPIFFE/OAuth 标准化剖面**——把 JWT 形态明确为同时满足 JWT-SVID + RFC 9068，把
X.509 形态明确为 X.509-SVID，让互操作落在公开标准而非私有约定上。

---

## 11. 实现落地对齐（2026-08-24）

以下能力已从设计稿进入实现：

### 11.1 SPIFFE（X.509 侧）

- **is_spiffe 模式**：`types/aic.go` 的 `BuildSPIFFEID/ValidateSPIFFEID/AddSPIFFESANToCert`；
  签发 API（`core/internal/serve/api_ops.go`）`is_spiffe + spiffe_trust_domain` 参数，
  签发时 agentId 双写为 `spiffe://<td>/agent/<id>` 并写入证书 SAN URI
  （`core/internal/ca/sign.go`）。
- **路径命名**：统一为单数 `/agent/`（`spiffe://<td>/agent/<agentId>`），与草案 §18 一致。
- **网关准入**：`gateway-core/spiffe.go`（解析/校验）+ `PipelineConfig` 新增
  `RequireSPIFFE / AllowedSPIFFEIDs / SPIFFETrustDomain`；TLS 配置
  `require_spiffe / allowed_spiffe_ids / spiffe_trust_domain`；http/tcp/udp 六处接线。
- **审计**：`AuditEntry.SPIFFEID`（`spiffe_id`）随连接/拒绝/插件决策写入，并进全文检索。

### 11.2 AIC-JWT（OAuth 侧）

- **核心实现源**：`types/aicjwt` 子包（claims/JWS/§6.2 能力匹配/约束/密钥绑定/11 步验证），
  复用 `types` 的 SPKI 哈希与 Capability（`CapToPKI/PKIToCap` 桥）。
- **独立参考仓库**：`aic-jwt` 改为 `replace` 引用
  `types/aicjwt` 的包装层，保留 OAuth 协议模拟（RFC 7523/8693/9449、状态列表、OBO）与场景测试。
- **草案 §18 规则**（revision 5）：`iss` 保持 OAuth URL（JWT-SVID 不读 iss，信任域由
  sub+bundle 锚定）；签发密钥 SHOULD 双发布（OAuth JWKS + SPIFFE bundle `use=jwt-svid`）；
  `typ` 保留 `aic+jwt`，跨生态出示需投影令牌（`typ=JWT` + 单 aud）；SPIFFE 模式下
  `sub` 直接继承 SPIFFE ID，零转换。

### 11.3 OAuth/OIDC 身份源

- `bridge-oauth`：OAuth/OIDC 身份源桥（Keycloak/Auth0/Okta/Entra/GitHub），
  多后端 token 缓存 + singleflight + userinfo 映射；core 的
  `identity-user` profile 经 `IdentitySourceOAuth`（`core/internal/ca/identity.go`）
  消费其 password grant + userinfo 端点，完成"身份源 → 基础身份证书"闭环。
- 定位：人的身份来源（LDAP/AD 对应 `bridge-ldap`），与 AIC 的 principal 绑定衔接，
  与 AIC-JWT 的 AS 侧签发互不重叠。

### 11.4 与草案的差异收敛

AIC-JWT 与 JWT-SVID 的令牌层差异已收敛为唯一硬冲突（`typ`），其余为增值语义；
部署层网关可将 SPIFFE ID 作为独立准入维度与 AIC 授权正交执行。
