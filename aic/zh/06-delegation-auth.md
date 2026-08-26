# DelegationAuthorization 签名与验证流程

> 代码：`core/internal/ca/aic.go`（签发）、`gateway-core/decision.go`（验证）

## 概述

DelegationAuthorization 是主体（用户）对 Agent 授权的密码学证据。用户持有实体证书，通过私钥对 Agent 的授权请求签名，网关用用户公钥验签。

## 数据结构

### DelegationAuthorization（证书内）

```asn1
DelegationAuthorization ::= SEQUENCE {
    reason              Reason,                          -- v1.7.1 新增：委托授权原因（必填）
    requestedLifetime   INTEGER (1..86400),
    timestamp           GeneralizedTime,
    nonce               OCTET STRING (SIZE(32)),
    signatureAlgorithm  AlgorithmIdentifier,
    signatureValue      OCTET STRING
}
```

> v1.7.1：`reason` 位于 DA 结构首位（必填），与 `DelegationAuthTBS.reason` 为同一委托原因，被签名覆盖。

### DelegationAuthTBS（签名目标）

用户的私钥签名的是 `DelegationAuthTBS` 的 DER 编码：

```asn1
DelegationAuthTBS ::= SEQUENCE {
    version                 INTEGER DEFAULT 1,
    agentId                 UTF8String (SIZE(1..256)),
    principalUid            PrincipalUid,
    reason                  Reason,                          -- v1.7.1 新增：委托授权原因（必填，被签名覆盖）
    capabilities            SEQUENCE SIZE(0..256) OF Capability,
    delegationMode          DelegationMode,
    authorizationConstraints [0] EXPLICIT SEQUENCE SIZE(0..32) OF Capability OPTIONAL,
    requestedLifetime       INTEGER (1..86400),              -- SHOULD 3600–86400
    timestamp               GeneralizedTime,                 -- MUST 使用 UTC（Z 形式）
    nonce                   OCTET STRING (SIZE(32))
}
```

> `Reason` 类型定义见 `01-asn1.md` §Reason（v1.7.1 新增，`reasonCode` 与 `description` 均 MUST 存在）。

> ⚠️ **v1.6 关键说明**：`authorizationConstraints` **MUST** 包含在签名覆盖范围内（位于 `DelegationAuthTBS` 中）。
> 这意味着：
> - 主体在签名授权时，已经知晓并同意了 `authorizationConstraints` 中的限制
> - 任何对 `authorizationConstraints` 的修改都需要主体重新签名
> - 网关在验证时，通过重建 TBS DER 并验签，天然确保证书中的约束与签名内容一致
>
> **v1.6.1 注意**：`PrincipalAuthorization.authorizationConstraints` 和 `AIC.authorizationConstraints` 分别在各自语义层独立检查（参见 `01-asn1.md` §PA 字段表格），不存在子集关系。
>
> **v1.7.1 注意**：`reason` 同时位于 `DelegationAuthTBS`（principalUid 之后，必填，被签名覆盖）与 `DelegationAuthorization`（结构首位，必填，证书内）两个结构——授权必有缘由。tag 约定见 `01-asn1.md` §编码标签约定。

> **查找说明**：按主体检索/关联（级联吊销、审计、证书查询）可通过 `principalUid.realm` / `identifier` 或数据库索引完成；验签定位仍以 `principalUid.keyHash` 为准，授权与吊销强绑定主体密钥，防止身份冒用。

## 签名流程

```
① 用户（主体）构造 DelegationAuthTBS
   ├── agentId:                    Agent 的唯一标识
   ├── principalUid:               主体身份（含 KeyHash）
   ├── reason:                     委托原因（v1.7.1，必填，reasonCode + description，被签名覆盖）
   ├── capabilities:               请求的能力列表
   ├── delegationMode:             authorized / representative
   ├── authorizationConstraints:   授权边界约束（v1.6，OPTIONAL，被签名覆盖）
   ├── requestedLifetime:          3600–86400 秒
   ├── timestamp:                  当前时间
   └── nonce:                      32 字节 CSPRNG 随机数

② 对 DelegationAuthTBS DER 编码做签名（ECDSA-SHA256 / RSA-SHA256，见 §签名算法要求）

③ 构造 DelegationAuthorization
   ├── reason:             同上（v1.7.1，与 TBS 中一致）
   ├── requestedLifetime: 同上
   ├── timestamp:          当前时间
   ├── nonce:              同上（32 字节）
   ├── signatureAlgorithm: 算法标识
   └── signatureValue:     签名值

④ 将 DelegationAuthorization 嵌入 AIC，提交 CA 签发
```

## 验证流程（CA 签发阶段）

```
① 验证 DelegationAuthTBS.timestamp 新鲜度（|now - timestamp| ≤ 30s）
② 验证 nonce 唯一性（CA 持久化已用 nonce，拒绝重复）
③ 用主体公钥验签 delegationAuthorization.signatureValue
④ 确认 capabilities 为 PrincipalAuthorization.grants 的能力级子集，且每条 capability 的 parameters 不超出对应 grant 的 parameters 边界（参数级子集，如有 PrincipalAuthorization）；越界即拒绝签发
⑤ 设置证书 NotAfter = now + requestedLifetime（授权有效期 = 证书有效期）
```

> **① timestamp 新鲜度已实现（P1-B-13）**：`POST /api/v1/certs`（agent-proxy 分支）与 `POST /api/v1/aic/issue` 在签发前校验 `|now - timestamp| ≤ da_max_timestamp_skew`（默认 30s，配置项 `serve.da_max_timestamp_skew`，设为 `"0"` 禁用）。与 ② nonce 唯一性共同构成说明书的"短时间窗口第二道防线"——DA 签名后拖延太久才提交签发（重放/盗签）即拒绝（403 `api.da_timestamp_stale`）。

## 验证流程（网关运行时）

参见 `gateway-core/decision.go:VerifyDelegationAuth`：

```
① 解析证书 AIC，提取 DelegationAuthorization
② 通过 principalUid.keyHash 定位主体公钥
③ 验证主体证书链至信任根
④ 用主体公钥验签 signatureValue（重建 DelegationAuthTBS DER，含 authorizationConstraints 与 reason（v1.7.1））
⑤ 交叉校验：hashAlgo(主体证书.SPKI) == AIC.PrincipalUid.KeyHash（当前实现 SHA-256）
```

> **网关不检查 timestamp 新鲜度和 Lifetime 过期**。CA 签发时已将 NotAfter 严格设为 `timestamp + requestedLifetime`，网关只需依赖标准 X.509 有效期检查（NotAfter）即完成生命周期校验。
>
> **可选加固（P1-B-13）**：`gateway-core` 的 `AdmissionConfig.CheckDAAge`（默认 false）+ `DAAgeMax`（默认 30s）可为需要更严格时间窗口的部署开启网关侧 DA timestamp 新鲜度校验；lib 同时提供 `CheckDAFreshness` 独立 helper。默认关闭以保持与上段设计一致。

> **主体证书链与吊销**：第③步的主体证书链验证及吊销检查（OCSP/CRL）MUST 由网关在调用 `VerifyDelegationAuth` 之前完成；`VerifyDelegationAuth` 仅负责验签与 SPKI 交叉校验。离线模式跳过在线吊销检查时 MUST 记录高风险审计（参见 `03-validation.md` §验证顺序）。

## 签名算法要求

`DelegationAuthorization.signatureAlgorithm` 声明委托签名算法，验证端 MUST 仅接受以下集合：

| 算法 | OID | 要求 |
|------|-----|------|
| ECDSA-SHA256 | `1.2.840.10045.4.3.2` | MUST 支持 |
| RSA-SHA256（PKCS#1 v1.5） | `1.2.840.113549.1.1.11` | MUST 支持 |
| RSA-SHA256（PSS） | `1.2.840.113549.1.1.10` | MUST 支持 |
| Ed25519 | `1.3.101.112` | MAY（可选实现） |
| SM2-SM3 | `1.3.6.1.4.1.66257.5.4` | 预留（国密，未启用） |

> 签名与验签 MUST 使用同一算法；密钥类型与算法不匹配（如 ECDSA 签名配 RSA 公钥）时拒绝。

## Nonce 生命周期

```
签发时：CA 校验 nonce 未用过 → 持久化到 da_nonces 表（32B）→ 写入 DelegationAuthTBS
运行时：网关收到连接 → 验签通过即放行（nonce 重放由 CA 签发时保证）
       网关 NonceCache 为可选增强（额外拦截重放，但不依赖）
```

> **Nonce 防重放的主体职责归属 CA（已实现）**：`POST /api/v1/certs`（agent-proxy 分支）与 `POST /api/v1/aic/issue` 在签发前对客户端签名携带的 32 字节 nonce 调用 `StoreDANonce`，同一 nonce 二次签发返回 403（`api.da_nonce_replayed`）。存储为 `da_nonces` 表（migration v29，MySQL `VARBINARY(32)`），内存引擎启用时引擎索引为权威、后台异步落库；引擎未启用时直写 DB。网关的 `NonceCache` 是可选优化，多网关集群或无状态部署下不依赖它。
> 
> **限制说明**：网关 `NonceCache` 是**进程本地缓存**，在多网关集群（如多个 `gateway-tcp` 实例负载均衡）中不共享。同一 nonce 被重放到不同网关节点无法被检测到。此限制是可接受的，因为 nonce 防重放的第一道防线由 CA 签发时的 DB 持久化保证，网关缓存仅作为额外加固。无状态网关部署应跳过 NonceCache。

## RequestedLifetime

- ASN.1 范围：`1 ≤ requestedLifetime ≤ 86400`（SHOULD 3600–86400）
- ASN.1 默认值：0（表示"未设置"）
- Go 层行为：0 自动升为 3600（1 小时）
- CA 签发策略：`NotAfter = now + min(requestedLifetime, 本地策略上限)`
- 运行时：网关只依赖 X.509 `NotAfter`，不检查 `timestamp + lifetime`

## SEQUENCE 编码示例

DelegationAuthTBS DER 结构字段顺序（Go `encoding/asn1` 序列化）：

| 序号 | 字段 | 说明 |
|------|------|------|
| 1 | version | INTEGER DEFAULT 1 |
| 2 | agentId | UTF8String |
| 3 | principalUid | PrincipalUid（SEQUENCE） |
| 4 | reason | Reason（SEQUENCE，必填，v1.7.1） |
| 5 | capabilities | SEQUENCE OF Capability |
| 6 | delegationMode | INTEGER (0..1) |
| 7 | authorizationConstraints | [0] EXPLICIT SEQUENCE OF Capability OPTIONAL（v1.6） |
| 8 | requestedLifetime | INTEGER |
| 9 | timestamp | GeneralizedTime |
| 10 | nonce | OCTET STRING (SIZE(32)) |

> 注意：字段顺序必须与 ASN.1 定义完全一致。增加或调整字段顺序会破坏所有已有签名的验证。`authorizationConstraints` 使用 `contextspecific,explicit,tag:0` 编码，OPTIONAL 字段不影响解析。
>
> v1.7.1：`reason` 位于第 4 位（principalUid 之后）且**必填**，缺失时解析/验签失败。

## 多级委托链（已实现 — gateway-core 2026-08-07）

> 历史状态：原为规范 FUTURE 预留。2026-08-07 于 `gateway-core` 落地递归验签实现，
> 用于企业端到端验证用例 8（张三→Scheduler-A→Worker-B 跨机器递归验证）。

### 架构

多级委托复用同一套 `DelegationAuthorization` 结构，递归使用形成可沿链逐级验证的密码学证据链：

```
Principal ──DA──▶ Agent A (chainDepth=0)
                     │
                     ├──DA──▶ Agent B (chainDepth=1)
                     │           │
                     │           ├──DA──▶ Agent C (chainDepth=2)
                     │           └── ...
                     └── ...
```

每一跳的 `DelegationAuthorization` 结构相同：

```
签名者（上一级 Agent / Principal）对 DelegationAuthTBS 签名
↓
接收方（下一级 Agent）将上一级的 DelegationAuthorization 嵌入自己的 AIC 扩展
↓
CA 签发时验签通过后签发新证书（client aic issue --user-cert=<上一级> --user-key=<上一级>）
↓
网关/Agent 验证时逐级逆向验签：Agent C → Agent B → Agent A → Principal
```

### 实现（lib 代码映射）

| 组件 | 代码 | 说明 |
|------|------|------|
| 递归验签器 | `DelegationChainVerifier`（decision.go） | `Verify(chain, topPrincipal)` 自底向上逐级验签 |
| 便捷入口 | `VerifyDelegationChain(chain, principal, maxDepth)` | 创建默认验证器 |
| 每级验签 | 复用 `VerifyDelegationAuth(aic, signerCert)` | DA 签名 + SPKI 交叉校验 |
| 链深度控制 | `MaxDepth` 字段 + `chainDepth ≤ maxDepth` 检查 | 超出即拒绝 |
| CLI 验证 | （未实现，可通过 `VerifyDelegationChain()` 程序化调用） | 输出逐级链验证日志 |

`chain` 参数为**从顶层往下**的证书列表（chain[0]=顶层委托 Agent，chain[len-1]=最底层 Agent）；
顶层 chain[0].AIC.DA 由 topPrincipal 证书签名，链中每级 AIC 的 DA 由上一级证书签名。
每级 AIC 签发时 `PrincipalUid.KeyHash` 必须 = 上一级（委托者）证书 SPKI 哈希 ——
client 的 `principalUidFromCert(cn, userCert)` 自动填充。

### 原理

- **复用已有结构**：`DelegationAuthorization` 本身已覆盖签名载体（TBS）、密码学算法、nonce、lifetime 等全部要素，多级委托**不需要新增 ASN.1 类型**
- **每一跳独立签名**：每级 Agent 使用自身私钥对下级授权信息签名，任何一跳被篡改均导致整链失败
- **整链离线可验证**：网关持有全部证书链即可逐级重建 TBS → 验签 → 检查 `chainDepth ≤ maxDepth`，不依赖任何外部服务
- **责任链密码学可追溯**：每一跳的签名证据固化在证书中，审计时可追溯到具体委托者

### 与单层委托的差异

| 维度 | 单层委托 | 多级委托 |
|------|---------|---------|
| `chainDepth` | 0（缺省） | 1+ |
| `DelegationAuthorization` 签名者 | Principal | 上一级 Agent |
| 验证路径 | 一步 | 逐级向上，直到 Principal |
| 网关变更量 | — | `DelegationChainVerifier` 递归验签 + 深度检查 |

### 安全约束

- `chainDepth ≤ maxDepth`：超出即拒绝（`Verify` 开头检查）
- `maxDepth` 由顶层 Principal 设定（调用方传入），整条链不可篡改（ASN.1 签名覆盖）
- 链中 Agent 证书 MUST 为终端实体证书（cA = FALSE）
- `nonce` 重放保护：每级委托使用独立 nonce，CA 签发时校验唯一性
