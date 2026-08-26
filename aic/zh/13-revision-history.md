# 变更记录

## 规范变更（2026-08-12，v1.7.2，OID 树瘦身）

| 变更 | 说明 |
|------|------|
| OID 树瘦身 | AIC 树仅保留核心三项：AgentIdentity（.1.1.1）、DelegationAuthorization（.1.1.2）、DelegationDepthControl（.1.1.4，FUTURE）；删除 AlgorithmSuite（.1.1.10，v1.5 已删未清理）、TransparencyInfo（.1.1.12，CT 走 6.x 或外部标准） |
| MarketAccess 归一级分支 | 仅保留 `.3.1` MarketAccessId；删除 AIC 树 .1.1.4 的 MarketAccessLite 残留（`OIDAICMarketAccess` 常量移除） |
| 3 分支清理 | 删除 EUDIWallet 占位（.3.4），3 分支后续另行规划 |
| 命名统一 | `OIDAICUserAuth` → `OIDAICDelegationAuthorization`（.1.1.2） |
| isKnownExtension | 移除 TransparencyInfo（.1.1.12）；DDC OID 常量已加（.1.1.4 系列，规范 §3.7），扩展解析待 P1-11 委托链实现时接线 |

## 实现增强（2026-08-12，P1-13/14/15/16，非规范变更）

| 变更 | 说明 |
|------|------|
| 插件审计级别区分（P1-13 / P2-A-28） | `gateway-core` `AuditEntry`/`PluginAuditEntry` 新增 `Level` 字段（JSON `level`）：pipeline 插件拒绝与执行错误 → WARN、允许 → INFO；`LogPluginDecision` 空 Level 按 Decision 推断，兼容旧调用方 |
| 未知约束严格模式（P1-14 / P1-B-23） | `AdmissionConfig.StrictConstraints`/`PipelineConfig.StrictConstraints`：默认关闭（未知约束审计告警+忽略，向前兼容），开启后 AIC 与 PA 两级未知 constraint 类型 fail-closed |
| 续签阈值百分比化（P1-15 / P2-A-11） | `NeedRenewPct`（默认 10%，`DefaultRenewPct`）与固定 2min 兜底并存（取 min）；三网关改用 `NeedRenewPct(cert,0)`；`NeedRenew` 固定窗口保留兼容 |
| agent-proxy 有效期上限可配置（P1-16 / P1-B-09/25 / P2-A-04） | agent-proxy（authorized 模式）证书有效期上限由硬编码 1h 改为 `SignConfig.MaxAgentProxyValidity`（`MaxAgentProxyValidityLimit()`，0 → 默认 1h）；配置项 `defaults.agent_proxy_max_validity`（默认 `1h`，≤24h 生效，超限忽略回退）；apiIssueCert / apiAICIssue / reissue 三入口注入 |

## 实现增强（2026-08-12，P1-10 / P1-B-13，非规范变更）

| 变更 | 说明 |
|------|------|
| DA timestamp 新鲜度防线落地 | CA 签发侧（`POST /api/v1/certs` agent-proxy 分支 + `POST /api/v1/aic/issue`）新增 `|now - timestamp| ≤ da_max_timestamp_skew` 校验（默认 30s，可配置，`"0"` 禁用），超窗拒绝 403 `api.da_timestamp_stale`；与 nonce 唯一性构成说明书"短时间窗口第二道防线"（06-delegation-auth.md §验证流程（CA 签发阶段）①） |
| 网关侧可选开关 | `gateway-core` `AdmissionConfig` 新增 `CheckDAAge`（默认 false）/`DAAgeMax`（默认 30s），`CheckDAFreshness` 独立 helper；默认关闭以保持"生命周期由 NotAfter 承担"的设计 |

## 实现增强（2026-08-12，P1-A-12，非规范变更）

| 变更 | 说明 |
|------|------|
| keyHash 算法族落地 | types `KeyHashFromSPKI` 支持 SHA-2/SHA-3 全族计算（SHA-256/384/512 + SHA3-256/384/512，共 6 种）；`MakePrincipalUidFromCertWithAlgo` 新增算法参数；`ValidatePrincipalUidKeyHash` 按 `hashAlgo` 输出长度校验（32/48/64 字节）；SM3/BLAKE2/BLAKE3 零外部依赖策略仅登记 OID+长度映射、显式报 unsupported 不静默降级；core 副本同步（`internal/ca/aic.go` 委托 types 映射表）。`MakePrincipalUidFromCert` 旧签名保持默认 SHA-256 向后兼容 |

## 实现增强（2026-08-07，非规范变更）

| 变更 | 说明 |
|------|------|
| 多级委托链落地 | `gateway-core` 新增 `DelegationChainVerifier` / `VerifyDelegationChain`：复用 `DelegationAuthorization` 结构（不新增 ASN.1 类型/OID），自底向上逐级验签 + `chainDepth ≤ maxDepth` 检查；`aicverify chain` CLI 递归验证。`DelegationDepthControl` OID（.1.1.4）仍为规范预留，未用于实现 |

## v1.7 → v1.7.1（2026-08-05）

| 变更 | 说明 |
|------|------|
| 新增 `Reason` 类型 | `SEQUENCE { reasonCode UTF8String, description UTF8String }`，`reasonCode` 与 `description` 均 MUST 存在且非空 |
| Reason 字段命名 | `code` → `reasonCode`、`display` → `description`（与 X.509 `reasonCode` 惯例对齐）；`reasonCode` 为受控词表（SCREAMING_SNAKE） |
| `DelegationAuthTBS` 新增 `reason` | 必填，位于 principalUid 之后，被主体签名覆盖 |
| `DelegationAuthorization` 新增 `reason` | 与 `DelegationAuthTBS.reason` 为同一委托原因，必填，位于结构首位；`reason` **不进入** `PrincipalAuthorization` |
| `reason` 必填化 | 授权必有缘由：`Reason` 在 DA/TBS 中为必填字段（非 OPTIONAL），避免空白授权 |
| 03-validation 新增 Reason 校验 | `reasonCode` 与 `description` 均 MUST 存在（R1/R2），`reasonCode` 建议 SCREAMING_SNAKE（R3），长度上限 `reasonCode`≤64 / `description`≤512（R4/R5） |
| 编码标签约定 | 所有 OPTIONAL 字段使用 context-specific `[n] EXPLICIT`，编号按结构内字段顺序从 0 开始；必填字段保持 universal tag（见 01-asn1.md §编码标签约定） |
| tag 重编号 | AIC constraints `[0]`/extensions `[1]`；TBS constraints `[0]`（reason 必填不打 tag）；DA 无 OPTIONAL 字段（reason 必填不打 tag）；PA constraints `[0]`/delegationPolicy `[1]`/extensions `[2]`；DelegationPolicy maxSessionHours `[0]`；PrincipalUid hashAlgo `[0]`；Capability parameters `[0]` |
| `DelegationMode` 类型 | `ENUMERATED` → `INTEGER (0..1)`（Go `encoding/asn1` 原生支持，跨语言实现一致） |
| 安全与完整性补强 | keyHash 校验按 hashAlgo 输出长度（当前 SHA-256 = 32 字节）；capabilities 与 authorizationConstraints 不得同时为空；capabilities 禁止 constraint schemeId |
| keyHash 算法化 | `keyHash = hashAlgo(SPKI)`，长度由算法决定（SIZE(1..64)）；规范不限定算法集合，当前实现 SHA-256，SM3 等后续通过 hashAlgo 扩展 |
| 约束 schemeId 白名单 | authorizationConstraints 的 schemeId MUST ∈ {constraint, constraint-v1, varwof/constraint-v1}，其他值拒绝 |
| Reason 长度上限 | reasonCode SIZE(1..64)、description SIZE(1..512)，reasonCode 应尽可能短 |
| DA 必填与双证书 | delegationAuthorization 为必填；双证书下握手证书与授权证书均为完整 AIC，均 MUST 携带 DA |
| TBS SIZE 统一 | TBS 与 AIC 对应字段约束一致（agentId 1..256、capabilities 0..256、constraints 0..8） |
| requestedLifetime 范围 | ASN.1 (1..86400)，SHOULD 3600–86400 |
| 能力参数子集校验明确 | `C_agent.parameters ⊆ P_grants.parameters` 在 CA 签发阶段机械校验（能力层，与能力级子集同层）；授权约束层不适用子集关系（v1.6.1 保持）；01-asn1 §Parameters 交集语义补执行层说明；06 CA 签发校验补参数级子集 |
| 编码与流程补强 | AIC/PA 扩展 MUST 非 critical；timestamp MUST UTC；主体证书链/吊销验证职责明确；签名算法集合明确（ECDSA-SHA256 / RSA-SHA256，Ed25519 MAY） |

## v1.6.1 → v1.7（2026-07-30）

| 变更 | 说明 |
|------|------|
| `signatureAlgo` → `signatureAlgorithm` | 与 X.509 RFC 5280 命名对齐（algorithmIdentifier） |
| `signature` → `signatureValue` | 与 X.509 RFC 5280 命名对齐（signatureValue） |
| DA 字段顺序确认 | requestedLifetime → timestamp → nonce → signatureAlgorithm → signatureValue（algorithm-before-value） |
| 06-delegation-auth DA 定义修正 | 06-delegation-auth.md 中 DA 字段顺序与 01-asn1.md 一致 |
| 02-code-map / 06-delegation-auth / README 引用更新 | 所有 `signature`/`signatureAlgo` 引用统一为新名称 |

## v1.6 → v1.6.1（2026-07-30）

| 变更 | 说明 |
|------|------|
| PrincipalAuthorization 新增 `authorizationConstraints` | PA 级别授权边界约束，复用 Capability 容器（`schemeId` ∈ {`constraint`, `constraint-v1`, `varwof/constraint-v1`}） |
| PA/AIC 约束独立检查 | PA 约束和 AIC 约束分别在各自语义层独立检查，不存在子集关系。PA 约束主体授权边界，AIC 约束 Agent 执行边界 |
| `CheckConstraintParameterBounds` 删除 | 参数边界交集校验语义错误：PA 和 AIC 约束不同层，不应强制子集关系 |
| 03-validation 决策模型更新 | 加入 `PA.authorizationConstraints` 项 |
| 07-capability 插件模型 | 明确为 JSON 文件配置，非 .so/外部进程 |
| 10-enterprise-profile | 新增 SPKI hash 查询 API 引用 |
| 01-asn1 PA 描述更新 | 字段表格明确 PA 约束与 AIC 约束独立 |

## v1.5 → v1.6（2026-07-30）

| 变更 | 说明 |
|------|------|
| 新增 `authorizationConstraints` 字段 | AIC 结构体 + DelegationAuthTBS |
| 约束复用 Capability 容器 | schemeId 固定为 `"constraint"` |
| 内置 3 种约束类型 | `allowed-cidr` / `max-concurrent` / `time-window` |
| 约束数量上限 | ≤ 32 条，单条 parameters ≤ 512 字节 |
| 网关离线检查 | TLS 握手阶段验证，不依赖外部系统 |
| 约束参数边界校验 | Agent 声明的参数值不超出主体（PrincipalAuthorization）授权范围 |
| 未知约束向前兼容 | 默认忽略 + 审计告警，`EnforceUnknownConstraints: true` 启用严格拒否 |
| 验证顺序固定 | 约束检查优先于能力检查（低成本快速拒绝） |
| DelegationAuthorization 签名覆盖约束 | VerifyDelegationAuth TBS 重建包含 authorizationConstraints |
| PrincipalAuthorization OID 修复 | `isKnownExtension` 列表 `.1.5` → `.1.2` |
| PrincipalUid 安全策略 | KeyHash 变更 = 新身份，存量证书 MUST 吊销 |
| Parameters 交集语义明确 | Agent 参数不越界，越界整条 Capability 无效 |
| 撤销在线/离线模式 | 在线 MUST OCSP/CRL，离线 fail-open + 高风险审计 |
| time-window 强制 UTC | `timezone` 字段废弃仅展示 |
| PrincipalUid 字符串仅展示 | 机器判 etc. 基于 ASN.1 结构体反序列化 |
| GatewaySession 逐步废弃 | HardTimeout/MaxRetries 移入网关本地策略配置 |
| 委托深度控制规范预留 | OID .1.1.4（DelegationDepthControl），chainDepth/maxDepth 字段定义，多级委托链架构描述。**暂不实现** |
| 证书体积上限明确 | 12KB 安全上限覆盖四网关，16KB QUIC 硬限制，256 caps 条目上限 |

## v1.4 → v1.5（2026-07-20）

| 变更 | 说明 |
|------|------|
| 删除 agentType | Agent 自治等级由 Capability 隐含表达 |
| 删除 AlgorithmSuite | 算法协商遵循 RFC 5280/TLS 1.3 |
| 删除 SPIFFE-Compatibility | 可选 Profile，非 Core |
| 删除 approvalScope/approvedCapIds | Capability 本身足够表达粒度 |
| 删除 VendorRegistry（AIC 子节点） | 移至 `.1.4` 独立分支 |
| 删除 PrincipalAuthorization.roles | 授权决策不得依赖角色标签 |
| 删除 PrincipalAuthorization.externalRef | 走 extensions 槽 |
| 删除 OfflineRBAC 独立扩展 | 由 Capability Scheme 实现 |
| 删除 UserExtensions | 由内置 extensions 槽覆盖 |
| 删除 PrincipalProfile | 组织属性由目录服务承载 |
| ExecutionConstraint 改为 Capability Scheme | 不再是独立 X.509 扩展 |
| 新增 Credential Bundle 概念 | 双凭证离线验证模型 |
| OID 树重构 | Core 仅保留 AIC、PrincipalAuthorization、Capability Registry |
| PrincipalUid.hashAlgo | 改为 AlgorithmIdentifier OPTIONAL，省略默认 SHA-256 |
| DelegationPolicy | 新增 version 字段 |
| DelegationAuthorization 新增 nonce | 必填 32 字节防重放 |
| DelegationAuthorization 新增 requestedLifetime | 3600-86400 秒，默认 3600 |

## v1.3 → v1.4（2026-07-13）

| 变更 | 说明 |
|------|------|
| DelegationAuthorization nonce 防重放 | 32 字节 CSPRNG 必填 |
| Offline Fail-Close 明确 | 任何验证失败即拒绝 |
| Capability 数量上限 | 256 条硬上限 |
| 机器主体支持说明 | realm 段可承载组织域名 |
| representative 证书轮换约束 | keyHash 不变则自动延续 |
| GDPR 被遗忘权缓解 | principalUid 使用 UUID |
| OCSP Must-Staple 要求 | 服务端证书签发时设置 |
| 证书体积约束 | 含全部扩展 ≤12KB |

## v1.2 → v1.3（2026-07-13）

| 变更 | 说明 |
|------|------|
| OID 树扩展 | 国密 SM2/SM3/SM4 + CT |
| algorithmSuite 激活 | PQC 算法套件 OID 占位 |
| ExecutionConstraint keyDerivation | HKDF 派生参数 |
| signerCache 缓存 | 已解密签名器内存缓存 |
| MemoryBuffer | 三种持久化模式 |
| 批量签发 API | 12 worker pool |

## v1.1 → v1.2（2026-07-12）

| 变更 | 说明 |
|------|------|
| OID 澄清 | principalUid 格式、PolicyRef/ExternalPolicyRef 区分 |
| 策略优先级裁决 | 5 级动态策略 |
| migrating 状态 | 续签旧证书临时豁免 quota |
| admin disconnect API | 管理员主动断开 |
| Glob 详细规则 | * / ** 通配语义 |

## v1.0 → v1.1（2026-07-12）

| 变更 | 说明 |
|------|------|
| PrincipalAuthorization | 用户权限声明扩展 |
| delegationMode | authorized / representative |
| approvalScope + approvedCapIds | 逐项签批 |
| 级联吊销 | principalUid 索引 |
| 审计 WAL + traceId | 完整性保障 |
| Capability glob 匹配 | * / ** 通配 |
| v1 委托限制 | 仅单层 Principal → Agent |

## v1.0（2026-07-10）

初始定稿。
