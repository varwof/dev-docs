# AIC × IAM Unification: Dual-Form Identity Design

> 状态：🟡 核心已部分落地（2026-08-24）：双形态身份已由 AIC-JWT（`draft-wei-aic-jwt-00`）+ `types/aicjwt` 实现；
> **FUTURE**：`/api/v1/token`（AIC→JWT 交换）、`/.well-known/jwks.json`、`/.well-known/openid-configuration`、策略点接口、多语言薄 SDK
> 日期：2026-08-01（更新 2026-08-24）
> 主题：AIC 作为 IAM 唯一身份源，任意主流语言、任意形态 App（原生/服务端/Web）原生接入

## 0. 一句话

AIC 已经是一张 X.509 证书，任何主流语言的 TLS 栈都能拿到它——但"能拿到证书"和"能原生
消费 AIC 语义"之间隔着一层 ASN.1。要达成"任意语言、任意形态 App 都原生支持 AIC + IAM
大一统"，关键不是给每种语言写 SDK，而是把 AIC 定义成**双形态身份**，让语言无关的标准
协议去承载它。

## 1. 大一统模型：AIC = IAM 的唯一身份源

```
                 ┌─────────────────────────────────────────────┐
                 │          AIC（身份源 / IAM 主体）              │
                 │  PrincipalUid · AgentId · Capabilities       │
                 │  ExecutionConstraints · 委派 · 吊销           │
                 └───────────────┬─────────────────────────────┘
                                 │ 两种自然形态（同一身份）
              ┌──────────────────┴──────────────────┐
              ▼                                     ▼
   形态一：X.509 证书（密码学原生）          形态二：JWT claims（语言中立）
   · mTLS peer cert 直达                     · 标准 JWT/JWKS，任意语言现成库
   · 网关 B2 透传 X-Client-Cert-DER          · Web 唯一路径（浏览器拿不到证书）
   · App 直接握手持证书                       · 短期、带 scopes/caps/constraints
              └──────────────────┬──────────────────┘
                                 ▼
              语言无关的接口约定（协议，不是 SDK）
```

**关键设计决策：AIC 身份投影为 JWT claims，而不是让每种语言解析 ASN.1。**
这是"最原生"的答案——Java/Node/Python/Rust/C#/PHP 全有成熟 JWT + JWKS 库，零自研。
SPIFFE/SPIRE 正是这个模式（X.509-SVID 与 JWT-SVID 双形态），AIC 可自然照此定义。

## 2. 身份到 App 的三条原生通道（按场景，不割裂）

| 场景 | 通道 | 应用侧拿到什么 | 语言怎么消费 |
|---|---|---|---|
| 服务端/原生 App | mTLS 直连 | TLS 层 peer cert（AIC） | 标准 TLS 栈取证书；证书→查核心 API 或本地缓存得 claims |
| 服务端经网关 | B2 证书透传 | `X-Client-Cert-DER` + 结构化头 | 任意 HTTP 栈读标准头；不信任，仅作上下文 |
| **Web App / 浏览器** | 短期身份令牌 | 标准 JWT（AIC 派生的 claims） | 标准 JWT 库验证 + 本地授权 |

Web 是唯一拿不到客户端证书的场景，所以必须有一个"用 AIC 换短期 JWT"的握手。这个握手
本身就是 IAM 大一统的枢纽：

```
Web App / 任意语言 App
   │  ① 持有 AIC 证书（mTLS 或经网关）
   ▼
核心  POST /api/v1/token    ← 用 AIC 交换短期 JWT（JWKS 签名）
   │  ② 返回 JWT: { sub=principal_uid, agent_id, scopes=capabilities,
   │                exp=min(证书有效期, ExecutionConstraints), ... }
   ▼
应用  GET /jwks → 标准 JWT 库验签 → 提取 claims → 本地执行策略
```

这样所有语言、所有形态的 App 只有**两个标准动作**：验 JWT（用 JWKS）+ 读 claims
（标准字段）。AIC 的 Capabilities 投影为 `scopes`，ExecutionConstraints 投影为
`exp/nbf` + 约束字段，PrincipalUid/AgentId 投影为 `sub` + 专属 claim——身份、权限、
策略三个维度全部语言中立。

## 3. 大一统的四个支柱

1. **身份识别**：`sub` = PrincipalUid，`agent_id` = AgentId，任何语言都认识 `sub`
   （OIDC 语义）
2. **权限控制**：`scopes` = AIC Capabilities（对应核心权限模型，如 `ca:issue`、
   `cert:revoke`）；应用做本地决策，不需要每次回核心
3. **执行策略**：JWT 内置 `exp/nbf`（ExecutionConstraints 硬超时投影）+ 审计链引用；
   复杂约束（CIDR、能力交集）由"策略点"执行——可内嵌（轻量）或调核心 `/authorize`
   （强一致）
4. **统一审计**：所有 App 消费同一 JWT，日志带同一 `sub`/`agent_id`/JWT id，Merkle
   链全程覆盖——从"认证到执行"整条链不割裂

## 4. 网关的定位随之清晰

网关不再是"身份中介"，而是**形态转换器**：X.509（客户端证书）→ 透传证书头（给服务端
App）或 → 换发 JWT（给 Web/跨语言）。核心仍是唯一签发源，网关只是通道 + 转换，不改
变信任模型。这也解释了 B2（证书透传）和 `/session`（身份探测）是这个模型的天然前两步。

## 5. 落地路径（语言无关，先协议后 SDK）

- **P0 协议层**：`/api/v1/token`（证书→JWT）+ `GET /jwks` + 标准 claim 映射表。这套
  接口定下来，任何语言都能直接接，**不需要等 SDK**
- **P1 参考实现**：给 2-3 种主流语言各写一个"薄"参考 SDK（验签 + claims 提取 + 本地
  授权助手），证明协议完备，其余语言按协议自实现
- **P2 策略点**：定义统一策略格式（JSON/Cedar/Rego 三选一），应用侧可本地评估或远端
  委托

## 6. 决策记录（2026-08-01 已定稿，未实现）

| # | 决策点 | 结论 |
|---|---|---|
| 1 | 中间表示 | **JWT/OIDC**（生态最广）；且统一 JWT 同时满足 SPIFFE JWT-SVID + RFC 9068（见 `11-spiffe-oauth.md`） |
| 2 | 策略评估部署形态 | **两级授权已定**：L1 内嵌（gateway 本地，粗粒度/离线）+ L2 集中式（core 在线 API，细粒度），按敏感度分级并存 |
| 3 | P1 参考 SDK 语言 | **Go + Python + Node** 三语言 |

> 附带定稿（2026-08-24 修订，对齐草案 §18）：`iss` 保持 OAuth/RFC 9068 URL（JWT-SVID 不读 iss，
> 信任域由 sub + SPIFFE bundle 锚定）、SPIFFE 模式下 `sub` 直接继承证书 agentId（即 SPIFFE ID）、
> token 端点接受 AIC mTLS + B2 + /session 三类通道。详见 `11-spiffe-oauth.md` §8/§11。

## 7. 与本仓库现状的衔接

- 已就绪：B2 证书透传（`X-Client-Cert-DER` + 结构化头）、`/api/v1/session` 身份探测、
  AIC 解析（`internal/ca` + pki-gateway-lib）、JWT 能力（OIDC provisioner 已有纯
  stdlib JWT 验签，可复用做签发）
- 待建：`/api/v1/token`（证书→JWT）、`/jwks`、claim 映射表、策略点接口
