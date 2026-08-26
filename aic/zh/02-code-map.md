# Go 结构 ↔ ASN.1 映射与代码定位

> 规范 v1.7.1（代码已对齐，2026-08-05 销项）。

> 2026-08-24 对齐附注
> - 当前模块名：`types`、`gateway-core`、`core`（旧名 `pki-types` / `pki-gateway-lib` / `pki-core` 已废弃）。
> - **AIC-JWT**：claims/JWS/能力匹配/约束/密钥绑定/11 步验证位于 `types/aicjwt/`
>   （`github.com/varwof/types/aicjwt`）；独立参考仓库 aic-jwt 为包装层 + OAuth 场景测试。
> - **SPIFFE**：`types/aic.go`（Build/Validate/AddSAN）、`gateway-core/spiffe.go`（解析/准入）、
>   `core/internal/ca/sign.go`（SAN 双写）、`core/internal/serve/api_ops.go`（is_spiffe 参数）。
> - **OAuth 身份源**：`bridge-oauth/`（桥接服务）、`core/internal/ca/identity.go`
>   （`IdentitySourceOAuth`，password grant + userinfo）。
> - 约束 schemeId 白名单：`varwof/constraint-v1`（规范推荐）、`constraint`、`constraint-v1`（向后兼容）；AIC/PA 约束数量上限 32 条。
>
> ✅ v1.7.1 已完成：
> - `Reason` 新增（DA 首位、TBS 在 principalUid 后），TBS 重建含 reason
> - 各结构 OPTIONAL 字段 tag 重编号（AIC constraints→[0]、extensions→[1]；PA constraints→[0]、delegationPolicy→[1]、extensions→[2]；DelegationPolicy.maxSessionHours→[0]）
> - `DelegationMode` / `DelegationModeEnum` 改为 INTEGER (0..1)
> - `PrincipalUid.hashAlgo` 改为 `AlgorithmIdentifier` 值类型（`[0] EXPLICIT OPTIONAL`，省略默认 SHA-256）
> - `AIC.delegationAuthorization` 语义必填（Go 保留 omitempty 以可 marshal，`BuildAIC`/`ParseAIC`/`ValidateAIC` 强制）
> - keyHash = hashAlgo(SPKI)：`ValidatePrincipalUidKeyHash` 按算法分派；约束 schemeId 白名单 `{constraint, constraint-v1, varwof/constraint-v1}`；非 SHA-256 显式"不支持"

> 已知限制：CA 签发阶段的**参数级子集校验**（`C_agent.parameters ⊆ P_grants.parameters`）尚未实现。该校验按能力层语义执行，不得套用到约束层，计划在后续版本提供。

## gateway-core（共享库）

| 文件 | Go 类型 | 对应 ASN.1 | 说明 |
|------|---------|-----------|------|
| `aic.go` | `AIC` | AIC SEQUENCE | 核心结构，含 authorizationConstraints（v1.7.1 constraints→[0]、extensions→[1]） |
| `aic.go` | `PrincipalUid` | PrincipalUid | String/ParsePrincipalUid/MakePrincipalUidFromCert + HashAlgoOID；hashAlgo 为 AlgorithmIdentifier 值类型 |
| `aic.go` | `DelegationAuthorization` | DelegationAuthorization | reason(首位) + requestedLifetime + timestamp + nonce + signatureAlgorithm + signatureValue（v1.7.1） |
| `aic.go` | `Capability` | Capability | schemeId + capabilityId + parameters（复用为约束容器） |
| `aic.go` | `ExtField` | ExtField | AIC 扩展槽条目 |
| `aic.go` | `AlgorithmIdentifier` | AlgorithmIdentifier | algorithm OID + parameters |
| `aic.go` | — | DelegationMode | Go const DelegationAuthorized(0) / DelegationRepresentative(1) |
| `types/user_permission.go` | `PrincipalAuthorization` | PrincipalAuthorization | grants + authorizationConstraints([0]) + delegationPolicy([1]) + extensions([2])（v1.7.1） |
| `types/user_permission.go` | `DelegationPolicy` | DelegationPolicy | version + maxAgents + allowedMode + maxSessionHours([0] value int) |
| `types/aic.go` | `DelegationAuthTBS` | DelegationAuthTBS | 签名覆盖结构，reason 在 principalUid 后，authorizationConstraints→[0] |
| `types/aic.go` | `ValidateAIC` / `ValidatePrincipalUidKeyHash` | — | v1.7.1 校验（R1–R5、V6、V8、V10/V15、V16、nonce 32B、约束白名单） |
| `decision.go` | `VerifyDelegationAuth` | — | TBS 重建（含 reason）+ 验签 + SPKI hash 交叉校验（ECDSA/RSA-SHA256/PSS） |
| `decision.go` | `CheckAuthorizationConstraints` | — | v1.6 离线验证 CIDR/并发/时间窗 |
| `pipeline.go` | `RunAccessPipeline` | — | 9 步统一准入管线（v1.6 含约束检查） |
| `plugin.go` | `PluginRegistry` | — | Capability Scheme 插件引擎 |

## core

| 文件 | Go 类型 | 对应 OID | 说明 |
|------|---------|---------|------|
| `internal/ca/oid.go` | OID 常量 | 全 OID 树 | 统一 OID 定义 |
| `internal/ca/aic.go` | AIC 签发结构 | `.1.1` | BuildAIC（含 V10/V15/V16/nonce 校验）+ ParseAIC（DA 缺失报错）+ ValidatePrincipalUidKeyHash + SPKIHash |
| `internal/ca/principal_auth.go` | PrincipalAuthorization / DelegationPolicy | `.1.2` | v1.7.1 三 tag（[0]/[1]/[2]）+ maxSessionHours [0] 值类型 |
| `internal/ca/sign.go` | ProfileAgentProxy | — | 签发 AIC 证书 |
| `internal/serve/api_ops.go` | API handlers | — | AIC 签发（DA 必带授权 400）、吊销 API |
| `internal/serve/rbac.go` | authenticate + authFromAIC | — | 角色提取 |

## gateway-{tcp,http,udp}

| 文件 | 功能 | 说明 |
|------|------|------|
| `gateway.go` | NewGateway | 统一构造函数，集成 lib 所有组件 |
| `mapping.go` / `proxy.go` | 数据面 | 调用 RunAccessPipeline 做准入 |

## OID → 代码映射

| OID | 名称 | 定义位置 | 解析位置 |
|:---:|------|---------|---------|
| `.1.1` | AIC | `core/internal/ca/oid.go` | `gateway-core/aic.go:ParseAIC` |
| `.1.1.1` | AgentIdentity | `core/internal/ca/oid.go` | 内嵌于 AIC |
| `.1.1.2` | DelegationAuthorization | `core/internal/ca/oid.go` | `gateway-core/decision.go:VerifyDelegationAuth` |
| `.1.2` | PrincipalAuthorization | `core/internal/ca/oid.go` | `gateway-core/decision.go` |
| `.1.2.4` | DelegationPolicy | `core/internal/ca/oid.go` | `gateway-core/decision.go` |
| `.1.6` | RenewalToken | `core/internal/ca/oid.go` | 预留 |
| `.3.1` | MarketAccessId | `core/internal/ca/oid.go` | 预留 |
| `.5.1` | SM2-Signature | `core/internal/ca/oid.go` | core 国密 |
| `.6.1` | SCT | `core/internal/ca/oid.go` | CT 日志 |

## ACL

以下功能在 v1.5 中从 Core 移除，相应 OID 保留但不再解析：

| OID | 移除项 | 替代方案 |
|:---:|--------|---------|
| `.1.1.4` | MarketAccessLite | 合并至 `.3.1` |
| `.1.1.5` | UserExtensions | AIC 内置 extensions 槽 |
| `.1.1.9` | VendorRegistry | 移至 `.1.4` |
| `.1.1.11` | SPIFFE-Compatibility | 可选 Profile |
| `.1.3` | OfflineRBAC | Capability Scheme |
| `.1.4` | PrincipalProfile | 目录服务 |
| `1.2` → `1.5` | PrincipalAuthorization OID 迁移 | OID 从 `.1.5` → `.1.2` |
