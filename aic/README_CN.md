# Varwof PKI 项目 — AIC 身份与授权规范

> [English](README.md)

> 版本：v1.7.1
> 日期：2026-08-26（持续更新；权威 OID 树见 `07-oid-tree.md`）
> 定稿（多级委托链为 FUTURE）

> **IPR 声明**：本文档受 BCP 79 (RFC 8179) 约束。作者已就本文档所述技术提交专利申请：
>
> - **CN2026112384541** — 一种基于 X.509 数字证书扩展的 AI Agent 身份与委托授权绑定的证书结构
> - **CN2026112384607** — 一种基于数字证书扩展的离线自包含网关授权与生命周期管理设备
>
> IPR 声明可通过 [IETF IPR 声明系统](https://datatracker.ietf.org/ipr/) 查询：
>
> - [IPR 7553](https://datatracker.ietf.org/ipr/7553) — Jijie Wei's Statement about IPR related to draft-wei-aic-identity-cert (2026-08-19)
> - [IPR 7565](https://datatracker.ietf.org/ipr/7565) — Jijie Wei's Statement about IPR related to draft-wei-aic-jwt (2026-08-24)
>
> 已提交 IPR 披露 7553 与 7565（BCP 79）。专利为防御性持有；实施者按上述披露获得免版税、合理且非歧视性许可。

## 概述

AIC（Agent Identity Certificate）是一套基于 X.509 v3 证书扩展的 AI Agent 身份与授权框架。它将 IAM 的授权结果（Principal Authorization + Capability）固化为不可篡改、可离线验证的证书结构，供 Gateway 在运行时执行。

### 三层平面

```
┌─────────────────────────────────────┐
│  IAM（Management Plane）            │  管理平面：定义身份、角色、授权
└──────────────┬──────────────────────┘
               │ 授权结果：PrincipalAuthorization + Capability
               ▼
┌─────────────────────────────────────┐
│  AIC / PKI（Trust Distribution）    │  分发平面：证书签发、身份绑定、证据固化
└──────────────┬──────────────────────┘
               │ 签发 Agent 证书
               ▼
┌─────────────────────────────────────┐
│  Gateway（Enforcement Plane）       │  执行平面：身份验证、权限交集、策略执行
└─────────────────────────────────────┘
```

### 设计原则

- **Core is stable; semantics are extensible** — 核心保持小而稳定，业务语义通过 Capability Scheme 扩展
- **Capability 是唯一容器** — Core 只定义 Capability 结构，不定义具体能力语义
- **用户证书为信任根** — 主体签名是授权的密码学锚点
- **离线自包含** — 验证方可在无网络环境下完成身份认证与授权决策
- **单层委托（默认），可扩展至多级委托链（FUTURE）** — Principal → Agent, 未来支持 Agent → sub-Agent
- **有限制但不越位** — 只把属于授权边界的约束放进证书（授权方决定、因人而异、变更频率低），不把运维策略、业务偏好、临时配置塞进证书
- **企业权限自治** — `PrincipalAuthorization` 扩展可独立于 Agent 委托，作为企业员工权限管理的基础设施

### 目录结构

#### 核心规范（稳定，可直接引用）

| 文件 | 内容 |
|------|------|
| [01-asn1.md](zh/01-asn1.md) | ASN.1 类型定义（AIC/DA/PA/Reason/PrincipalUid） |
| [02-code-map.md](zh/02-code-map.md) | Go 结构 ↔ ASN.1 映射 + 代码定位 |
| [03-validation.md](zh/03-validation.md) | ValidateAIC 校验规则（V6/V8/R1-R10） |
| [04-examples.md](zh/04-examples.md) | 编解码示例（DER/PEM/JSON） |
| [05-capability.md](zh/05-capability.md) | Capability 规范（字符串格式、Parameters、Glob 匹配、内置方案） |
| [06-delegation-auth.md](zh/06-delegation-auth.md) | DelegationAuthorization 签名与验证流程 |
| [07-oid-tree.md](zh/07-oid-tree.md) | OID 树（1.3.6.1.4.1.66257） |

#### 部署模式（FUTURE / 部分实现）

| 文件 | 内容 | 状态 |
|------|------|------|
| [08-dual-cert.md](zh/08-dual-cert.md) | 双证书部署方案（握手证书 + 授权证书，绕过 QUIC 16KB 限制） | FUTURE |
| [09-aic-iam-unification.md](zh/09-aic-iam-unification.md) | AIC × IAM 统一身份（双形态：X.509 + JWT） | 🟡 部分实现 |
| [10-enterprise-authz.md](zh/10-enterprise-authz.md) | 企业权限自治（PrincipalAuthorization + authz.json） | 🟡 部分实现 |
| [11-spiffe-oauth.md](zh/11-spiffe-oauth.md) | AIC × SPIFFE × OAuth/OIDC 互操作规范 | ⚠️ 暂缓 |
| [12-identity-source.md](zh/12-identity-source.md) | LDAP/AD 身份来源整合（bridge-ldap/bridge-oauth） | ⚠️ 暂缓 |

#### 参考

| 文件 | 内容 |
|------|------|
| [13-revision-history.md](zh/13-revision-history.md) | 变更日志（v1.0 → v1.8） |
| [14-version-governance.md](zh/14-version-governance.md) | 版本治理策略（冻结/发布流程） |

## OID 树

### 根 OID

```
1.3.6.1.4.1.66257 (IANA PEN — Varwof PKI Project)
```

IANA PEN 66257，已于 2026 年 7 月正式批复。

### 正式 OID 树

```
1.3.6.1.4.1.66257
│
├── 1  身份与权限核心 (Core Identity & Authorization)
│   ├── 1  AIC                     ── Agent 身份证书扩展
│   │   ├── 1  AgentIdentity       ── agentId, principalUid, delegationMode
│   │   ├── 2  DelegationAuthorization ── 主体签名证据
│   │   ├── 4  DelegationDepthControl  ── (FUTURE) 委托深度控制
│   │   │   ├── 1  chainDepth      ── 当前委托层级
│   │   │   └── 2  maxDepth        ── 最大允许委托深度
│   │
│   ├── 2  PrincipalAuthorization  ── 主体授权声明；delegationPolicy 是扩展内 ASN.1 字段，非子 OID
│   │
│   ├── 3  OfflineRBAC            ── 已删除（2026-08）：值 .1.3，无生产调用
│   ├── 4  PrincipalProfile       ── 已删除（2026-08）：值 .1.4，无生产调用
│   ├── 5  GatewaySession (historical) ── v1.5 前网关会话扩展（已迁移至 AIC.authorizationConstraints）；保留分支用于 gateway 相关子 OID
│   │   └── 1  子 CA scope        ── 在用：子 CA 作用域 .1.5.1，生产使用中
│   └── 6  RenewalToken            ── (预留) 授权续期令牌
│
├── 2  ASN.1 模块标识
│   └── 1  id-mod-varwof-aic       ── ASN.1 模块弧 { 1 3 6 1 4 1 66257 2 1 }（I-D §1.3）
│
├── 3  国家/行业认证
│   ├── 1  MarketAccessId          ── 市场准入容器
│   ├── 2  TrustLevel              ── 信任等级
│   └── 3  CrossBorder             ── (预留) 跨境互认
│
├── 5  国密算法标识
│   ├── 1  SM2-Signature
│   ├── 2  SM3-Hash
│   ├── 3  SM4-Encryption
│   └── 4  SM2-SM3-Signature
│
└── 6  证书透明度集成
    ├── 1  SCT                     ── SignedCertificateTimestamp
    └── 2  CTLog                   ── CT 日志标识
```

### OID 映射表

| OID | 名称 | 类型 |
|:---:|------|:----:|
| `1.3.6.1.4.1.66257.1.1` | AIC | X.509 扩展 |
| `.1.1.1` | AgentIdentity | AIC 子节点 |
| `.1.1.2` | DelegationAuthorization | AIC 子节点 |
| `.1.1.4` | DelegationDepthControl | AIC 子节点（FUTURE） |
| `.1.1.4.1` | chainDepth | DDC 子节点（FUTURE） |
| `.1.1.4.2` | maxDepth | DDC 子节点（FUTURE） |
| `.1.2` | PrincipalAuthorization | X.509 扩展 |
| `.1.3` | OfflineRBAC | 已删除：无生产调用 |
| `.1.4` | PrincipalProfile | 已删除：无生产调用 |
| `.1.5` | GatewaySession | 历史网关会话扩展（子 CA scope .1.5.1 生产使用中） |
| `.1.5.1` | 子 CA scope | CA 作用域扩展（在用） |
| `.1.6` | RenewalToken | 授权续期令牌 |
| `.2.1` | id-mod-varwof-aic | ASN.1 模块标识（I-D §1.3） |
| `.3.1` | MarketAccessId | 国家认证扩展 |
| `.3.2` | TrustLevel | 信任等级 |
| `.5.1` | SM2-Signature | 国密算法 |
| `.5.2` | SM3-Hash | 国密算法 |
| `.5.3` | SM4-Encryption | 国密算法 |
| `.5.4` | SM2-SM3-Signature | 国密算法 |
| `.6.1` | SCT | CT 扩展 |
| `.6.2` | CTLog | CT 扩展 |

> 设计原则：Core 仅维护身份、授权和能力容器。算法套件、执行策略参数、Certificate Transparency 等均通过外部标准或 Capability Scheme 扩展，不在 Core OID 树中重复定义。v1.6 新增的 `authorizationConstraints` 复用 Capability 容器，不新增 OID。

## 授权验证流程

接收方在完成证书链验证后，依次执行：

1. **提取** AIC
2. **定位主体公钥** — 通过 principalUid.keyHash 在凭证包中匹配
3. **验证主体证书链** 至信任根
4. **验签** — 用主体公钥验证 delegationAuthorization.signatureValue
5. **CA 验证 DelegationAuthTBS** — timestamp 新鲜度 + nonce 唯一性（签发协议阶段）
6. **判别委托模式** — authorized 仅用 capabilities；representative 需校验 capabilities ⊆ PrincipalAuthorization.grants
7. **检查 chainDepth ≤ maxDepth（FUTURE）** — 多级委托链深度控制
8. **检查 authorizationConstraints** — **先检查约束（低成本快速拒绝）**，所有约束 MUST 同时满足（AND 逻辑）
9. **检查 capabilities** — 再检查业务能力
10. **执行 Capability Scheme 路由** — 按 schemeId 分发至插件
11. **应用 Gateway Policy** — 运行时策略（超时/重试/限流/路由）
12. **审计日志** — 记录 agentId、principalUid、decision、timestamp

> 第 7–8 步顺序固定：约束检查（时间/IP/并发）比业务能力检查成本更低，应在 TLS 握手阶段优先执行，快速拒绝不合规请求。

## 部署剖面

### 标准部署（单证书）

Agent 持有一张完整的 AIC 证书（含 capabilities + authorizationConstraints），在 TLS 握手时一次性出示。适用于 TCP/HTTP mTLS 等 Certificate 消息无体积限制的协议。

### 双证书部署（握手证书 + 授权证书）

> 详见 [`08-dual-cert.md`](zh/08-dual-cert.md)

在 QUIC/DTLS 环境中，由于 TLS 握手阶段 Certificate 消息存在约 16KB 的硬性限制（RFC 9000），部署时 MAY 将 AIC 证书拆分为：

- **握手证书**：仅包含 `agentId`、`principalUid`、`delegationMode`、`DelegationAuthorization`，用于 mTLS 握手；`capabilities` 至少一条（AIC 校验要求非空，具体占位能力由部署按注册表定义）。SHOULD NOT 超过 8KB。
- **授权证书**：包含 `capabilities`、`authorizationConstraints` 及扩展信息，在握手完成后通过应用层传输。SHOULD NOT 超过 64KB。

两个证书由同一 CA 签发，信任链一致。此方案是部署策略优化，不改变 AIC 协议定义。
