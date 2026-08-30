# OID 树梳理：1.3.6.1.4.1.66257（2026-08-12，v1.7.2 瘦身后）

> 依据：规范 `AIC-身份与授权技术规范-1.7.1.md`（2.2/2.3/10.4/10.5/12 变更记录）、`types/oid.go`、`core/internal/ca/oid.go`。
> 根：1.3.6.1.4.1.66257（IANA PEN 66257 — Varwof PKI）。2026-08-12 v1.7.2 起 AIC 树只保留核心三项，非核心项移出规范、由实现侧或外部标准承载。

---

## 一、正式 OID 树（规范 1.7.2 现状）

```
1.3.6.1.4.1.66257
│
├── 1  身份与权限核心 (Core Identity & Authorization)
│   ├── 1  AIC  ── Agent 身份证书扩展
│   │   ├── 1  AgentIdentity       ── 保留子节点（内嵌字段：agentId, principalUid, delegationMode；非独立扩展，不在 isKnownExtension）
│   │   ├── 2  DelegationAuthorization ── 保留子节点（内嵌签名证据 .1.1.2；代码常量 OIDAICDelegationAuthorization，v1.7.2 由旧名 UserAuth 统一；非独立扩展，不在 isKnownExtension）
│   │   └── 4  DelegationDepthControl  ── (FUTURE) 委托深度控制
│   │       ├── 1  chainDepth      ── 当前委托层级
│   │       └── 2  maxDepth        ── 最大允许委托深度
│   │
│   ├── 2  PrincipalAuthorization  ── 占用：主体授权声明（v1.5 起，由 .1.5 迁移）；
│   │       delegationPolicy 是扩展内的 ASN.1 字段（[1] EXPLICIT），不是子 OID，无 .1.2.4
│   ├── 3  OfflineRBAC            ── 已删除（2026-08）：gateway-core 离线 RBAC 扩展，值 .1.3，无生产调用（见第三节）
│   ├── 4  PrincipalProfile       ── 已删除（2026-08）：gateway-core 身份档案扩展，值 .1.4，无生产调用（见第三节）
│   ├── 5  GatewaySession (historical) ── v1.5 前网关会话扩展（已迁移至 AIC.authorizationConstraints）；
│   │       保留该分支用于后续 gateway 相关子 OID（如下方子 CA scope）
│   │   └── 1  子 CA scope         ── 在用：子 CA 作用域扩展 .1.5.1，生产使用中（core sign/sub 校验）
│   └── 6  RenewalToken            ── (预留) 授权续期令牌
│
├── 2  ASN.1 模块标识
│   └── 1  id-mod-varwof-aic       ── ASN.1 模块弧 { 1 3 6 1 4 1 66257 2 1 }（I-D §1.3）
│
├── 3  国家/行业认证（v1.7.2 清理，后续另行规划）
│   ├── 1  MarketAccessId          ── 市场准入容器（完整凭证）
│   ├── 2  TrustLevel              ── 信任等级
│   └── 3  CrossBorder             ── (预留) 跨境互认
│   （.3.4 EUDIWallet 已删除，2026-08-12）
│
├── 5  国密算法标识
│   ├── 1  SM2-Signature
│   ├── 2  SM3-Hash
│   ├── 3  SM4-Encryption
│   └── 4  SM2-SM3-Signature
│
└── 6  证书透明度集成（TransparencyInfo 不再在 AIC 树占位，CT 走本分支或 RFC 6962）
    ├── 1  SCT                     ── SignedCertificateTimestamp
    └── 2  CTLog                   ── CT 日志标识
```

## 二、v1.7.2 移除项

| 原槽位 | 原名称 | 处理 | 说明 |
|:---:|------|------|------|
| .1.1.4 | MarketAccessLite（OIDAICMarketAccess） | 移除 | MarketAccess 归一级分支 `.3.1` MarketAccessId；代码常量删除（v1.5 已标 DEPRECATED） |
| .1.1.10 | AlgorithmSuite | 删除 | v1.5 变更记录已"删除"，本次清理树/映射表/对照表残留；算法协商走 RFC 5280/TLS 1.3 |
| .1.1.12 | TransparencyInfo | 移出 | CT 走 6.x 分支（.6.1 SCT / .6.2 CTLog）或 RFC 6962；isKnownExtension 同步移除 |
| .3.4 | EUDIWallet | 删除 | eIDAS 2.0 暂缓，3 分支后续另行规划 |
| .1.1.2 | OIDAICUserAuth（旧名） | 更名 | 统一为 OIDAICDelegationAuthorization（值不变） |

## 三、AIC 树（.1.1.x）槽位占用（瘦身后）

| 槽位 | 名称 | 状态 |
|:---:|------|------|
| .1.1.1 | AgentIdentity | 占用 |
| .1.1.2 | DelegationAuthorization | 占用 |
| .1.1.3 | — | 空闲（未分配） |
| .1.1.4 | DelegationDepthControl | (FUTURE) 规范预留，暂不实现 |
| .1.1.5 | UserExtensions | 已移除（v1.5） |
| .1.1.6 | — | 空闲 |
| .1.1.7 | — | 空闲（未分配） |
| .1.1.8 | — | 空闲 |
| .1.1.9 | VendorRegistry | 已移除（v1.5） |
| .1.1.10 | AlgorithmSuite | 已删除（v1.7.2 清理） |
| .1.1.11 | SPIFFE-Compatibility | 已移除（v1.5） |
| .1.1.12 | TransparencyInfo | 已移出（v1.7.2） |

## 四、代码与规范一致性（2026-08-12 已对齐）

- `types/oid.go`：删 `OIDAICMarketAccess`、AlgorithmSuite 系列、`OIDEUDIWallet`；`OIDAICUserAuth` → `OIDAICDelegationAuthorization`。
- `gateway-core/aic.go`：删除 AlgorithmSuite 重新导出行。
- `core/internal/ca/oid.go` + `oid_test.go`：同步（子模块，2026-08-12 提交）。
- `evidence/e1-aic-size/main.go`：扩展模拟改用 `OIDAICDelegationAuthorization`。
- 规范 1.7.1 → 1.7.2：树/映射表/已知扩展/对照表/变更记录已同步。
- 待接线：DelegationDepthControl（.1.1.4）常量已加（`OIDDelegationDepthControl`/`OIDDDCChainDepth`/`OIDDDCMaxDepth`），扩展解析随 P1-11 委托链防环/递归求交实现（说明书 172 行保持不变）。

## 五、相关链接

- 规范：`AIC-身份与授权技术规范-1.7.1.md` §2.2/2.3/3.7/10.4/10.5/12（v1.7.2）
- 代码：`types/oid.go`、`core/internal/ca/oid.go`
- 修订史：`dev-docs/aic/13-revision-history.md`（OID 树瘦身、P1-10/13/14/15/16 实现增强）
