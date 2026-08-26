# ValidateAIC 校验规则

> 代码：`gateway-core/aic.go:ValidateAIC`

校验在 `ParseAIC` 之后、`CheckAdmission` 之前调用。

## 核心校验项

| # | 检查 | 规则 | 违反时 |
|---|------|------|--------|
| 1 | Capability 数量上限 | `len(capabilities) ≤ 256` | 拒绝 |
| 2 | schemeId 长度 | `1 ≤ len(schemeId) ≤ 128` | 拒绝 |
| 3 | capabilityId 长度 | `1 ≤ len(capabilityId) ≤ 256` | 拒绝 |
| 4 | parameters 长度 | `len(parameters) ≤ 4096` | 拒绝 |
| 5 | Extensions 未知 critical | 未知 OID 且 critical=TRUE | 拒绝 |
| 6 | principalUid.realm 长度 | `1 ≤ len(realm) ≤ 128`（ASN.1 `SIZE(1..128)`） | 拒绝 |
| 7 | principalUid.identifier 长度 | `1 ≤ len(identifier) ≤ 256`（ASN.1 `SIZE(1..256)`） | 拒绝 |
| 8 | keyHash 长度 | 规范 `1 ≤ len(keyHash) ≤ 64`（`SIZE(1..64)`，仅支持输出长度≤64字节的哈希算法族）；须等于 `hashAlgo` 声明的输出长度——当前实现支持 SHA-2/SHA-3 全族（SHA-256=32/SHA-384=48/SHA-512=64/SHA3-256=32/SHA3-384=48/SHA3-512=64 字节）；长度不符或 SM3/BLAKE2/BLAKE3 等需外部依赖的算法显式报 unsupported（P1-A-12） | 拒绝 |
| 9 | nonce 长度 | `len(nonce) == 32` | 拒绝 |
| 10 | requestedLifetime 范围 | `1 ≤ lifetime ≤ 86400`（SHOULD ≥ 3600） | 拒绝 |

> 注：`0 → 3600` 升级仅存在于 **API 输入层归一化**（调用方传 0 按默认 3600 处理）；编码进 TBS/DA 的 wire 值必须已在 1..86400 范围内，ASN.1 定义为 `INTEGER (1..86400)`，无 DEFAULT 0。
| 11 | capabilities 禁止约束 schemeId | 每条 MUST NOT `schemeId = "varwof/constraint-v1"` | 拒绝 |
| 12 | 非空授权 | `capabilities` 不得为空（至少一条，CA 签发策略 MUST）；`authorizationConstraints` 可为空（空 = 不限制） | 拒绝签发 |

## authorizationConstraints 校验（v1.6）

### AIC 级约束校验

| # | 检查 | 规则 |
|---|------|------|
| C1 | 约束数量上限 | `len(constraints) ≤ 32` |
| C2 | schemeId 白名单 | 每条 MUST 为 `"varwof/constraint-v1"`（规范推荐）、`"constraint"` 或 `"constraint-v1"`（向后兼容）；其他值拒绝 |
| C3 | capabilityId 识别 | SHOULD 为 `network:cidr` / `session:max-concurrent` / `time:window` / `geo-fence` 之一；未知类型默认**记录审计告警并忽略**（不阻断业务），若运维配置 `StrictConstraints: true` 则拒绝 |
| C4 | parameters JSON 可解析 | MUST 为合法 JSON（`json.Valid`），仅针对约束类型（varwof/constraint-v1 白名单）的 parameters——内置约束格式由本规范定义；业务能力（非约束 schemeId）的 parameters 为不透明字节串，编码由 schemeId 方案定义（推荐 JSON，允许 CBOR/ASN.1/二进制等） |
| C5 | 单条 parameters 大小 | ≤ 512 字节（UTF-8 编码后） |
| C6 | capabilityId 非空 | MUST 非空字符串 |

### PA 级约束校验（v1.6.1）

PA 的 `authorizationConstraints` 遵循与 AIC 相同的格式规则：

| # | 检查 | 规则 |
|---|------|------|
| P1 | 约束数量上限 | `len(constraints) ≤ 32` |
| P2 | schemeId 白名单 | 每条 MUST 为 `"varwof/constraint-v1"`（规范推荐）、`"constraint"` 或 `"constraint-v1"`（向后兼容）；其他值拒绝 |
| P3 | capabilityId 非空 | MUST 非空字符串 |
| P4 | parameters JSON 可解析 | MUST 为合法 JSON |
| P5 | 单条 parameters 大小 | ≤ 512 字节 |
| P6 | 运行时检查 | PA 约束遇到不支持的约束类型时**降级审计告警并忽略**（同 AIC 宽松策略） |

PA 约束**独立于** AIC 约束执行：直接访问（无 AIC）时 PA 约束是唯一约束；委托访问时 PA 和 AIC 约束在各自层独立检查，不存在子集关系。

> **默认宽松（Forward-Compatible）**：未知约束类型被忽略，确保新旧网关混部时新约束可灰度上线。严格模式由运维配置开关控制。

### 约束参数校验细则

#### `network:cidr`

支持两种 JSON 形态（网关均接受）：

```json
["10.0.0.0/8", "192.168.0.0/16"]
```

```json
{"cidrs": ["10.0.0.0/8", "192.168.0.0/16"]}
```

- MUST 为 JSON 数组，或 `{"cidrs": [...]}` 对象
- 每项 MUST 为合法 CIDR 字符串
- 空列表 = 不限制（等价于无此约束）
- 需网关提供连接对端 IP（`ClientIP`）；IP 为空时约束跳过（无法评估来源地址）

#### `session:max-concurrent`

```json
{"max": 5}
```

- `max` MUST 为整数，1 ≤ max ≤ 1024
- 由网关连接跟踪器检查，约束评估阶段跳过（占位类型）

#### `time:window`

```json
{"start": "22:00", "end": "06:00"}
```

```json
{"start": "09:00", "end": "18:00", "tz": "Asia/Shanghai"}
```

- `start` / `end` MUST 为 `HH:MM` 格式（00:00–23:59）
- `tz` 为 IANA 时区名（可选）：窗口时间按该时区解释，评估时自动换算；缺省按 **UTC** 评估（向后兼容）
- 跨天窗口（start > end）表示跨日（如 22:00–06:00）
- 窗口含起点不含终点（09:00–18:00 在 18:00 整点时已出窗）

#### `geo-fence`

支持内联表与外部 resolver 两种形态：

```json
{"resolver": "inline", "regions": {"CN-SHA": ["10.0.0.0/8", "192.168.0.0/16"]}}
```

```json
{"resolver": "ip2region", "regions": ["CN-SHA", "CN-BJS"]}
```

- `resolver` 为地域解析器名：`inline`（默认，零外部依赖，regions 为 region→CIDR 内联表，IP 命中任一 CIDR 即归属该地域）或外部解析器
- 外部 resolver 需先在网关注册（`RegisterGeoResolver`，如 ip2region）；**未注册的 resolver 评估失败 = 拒绝连接（fail-closed），而非静默放行**
- `regions` 为允许的地域标识集合，客户端 IP 解析出的地域标识必须命中
- 需网关提供连接对端 IP；IP 为空时约束跳过

## Reason 校验（v1.7.1）

`DelegationAuthorization.reason` 与 `DelegationAuthTBS.reason` 复用同一 `Reason` 结构（定义见 `01-asn1.md` §Reason）。`reason` 为**必填**字段（授权必有缘由），说明性用途（审计/展示），不参与权限决策；校验失败仅拒绝证书/签名，不影响授权交集计算。

| # | 检查 | 规则 |
|---|------|------|
| R1 | `reasonCode` 存在 | MUST 存在且非空（UTF8String） |
| R2 | `description` 存在 | MUST 存在且非空（UTF8String） |
| R3 | `reasonCode` 取值风格 | SHOULD 为 SCREAMING_SNAKE（受控词表，如 `SCHEDULED_MAINTENANCE`） |
| R4 | `reasonCode` 长度 | MUST ≤ 64 字符，应尽可能短 |
| R5 | `description` 长度 | MUST ≤ 512 字符 |

## Extensions 已知 OID 列表

`isKnownExtension` 识别以下 OID：

| OID | 名称 |
|:---:|------|
| `.1.1.1` | AgentIdentity |
| `.1.1.2` | DelegationAuthorization |
| `.1.2` | PrincipalAuthorization |
| `.3.1` | MarketAccessId |

其他 OID 且 `critical=true` 将导致拒绝。

> AIC 与 PrincipalAuthorization 扩展自身 MUST 为非 critical（`critical=TRUE` 按未知扩展拒绝），以保证非 AIC 感知系统可安全忽略。

## AdmissionConfig 选项

`AdmissionConfig` 提供更细粒度的运行时准入控制：

| 选项 | 默认 | 说明 |
|------|------|------|
| `RequireAIC` | false | 拒绝不含 AIC 扩展的连接 |
| `RequiredProtocol` | "" | 要求 Agent 具备指定 SchemeId |
| `RequiredCapabilities` | nil | 要求 Agent 具备全部指定能力；匹配为 glob 通配（`MatchCapability`），AIC 声明（裸 capabilityId 或 `schemeId:capabilityId`）作为模式，声明侧通配可覆盖带细节的要求——如声明 `SELECT:*`（完整名 `mysql:SELECT:*`）覆盖要求 `mysql:SELECT:*` / `mysql:SELECT:/api/tables`，但 `mysql:INSERT:*` / `http:GET:/admin` 拒绝 |
| `DisallowRepresentative` | false | 拒绝代表模式 |
| `RequireUserAuth` | false | 要求 DelegationAuthorization 签名验证通过 |
| `EnforceCapSizeConstraints` | false | 验证 Capability 字段长度 |
| `NonceCache` | nil | nonce 重放保护缓存（nil=跳过） |
| `EnforceSize32` | false | 验证 nonce 为 32 字节 |
| `EnforceConstraints` | false | v1.6 是否强制执行 authorizationConstraints，PA 级和 AIC 级均受此开关控制 |

### EnforceConstraints 行为

| 约束类型 | 检查逻辑 | 违反时 |
|---------|---------|--------|
| `network:cidr` | 连接对端 IP 是否在任一 CIDR 中 | 拒绝 |
| `session:max-concurrent` | 当前该 Agent 活跃连接数是否已达上限 | 拒绝 |
| `time:window` | 当前时间是否在窗口内（按 tz 换算，缺省 UTC） | 拒绝 |
| `geo-fence` | 连接对端 IP 解析出的地域标识是否在允许集合内 | 拒绝 |
| 未知类型 | 记录审计告警并忽略（宽松）；严格模式可拒绝 | 视配置 |

## 验证顺序（v1.6.1 明确双级约束）

网关完成 TLS 握手后，按以下顺序执行验证：

```
1. 证书链验证                          ← 标准 X.509 路径构建
   ├── 网络可达时：MUST 校验 OCSP Stapling 或 CRL，未通过则拒绝
   └── 网络不可达/离线模式：跳过在线撤销检查（fail-open），
       记录高风险审计日志；**强制**证书剩余有效期 ≤ 1h
       （G2(b) 已实现：ocsp_fallback=allow 时网关注入
       OfflineMaxCertLifetime=1h，超限拒绝）
2. 解析 AICExtension                   ← 提取身份 + 能力 + 约束
3. 验证 DelegationAuthorization        ← 主体签名验签 + SPKI hash 交叉校验
4. 检查 chainDepth ≤ maxDepth（FUTURE）← 多级委托链深度控制，单层部署可省略
5. **检查 PA.authorizationConstraints** ← v1.6.1，PA 约束独立于 AIC 约束
6. 检查 AIC.authorizationConstraints   ← 优先执行，低成本快速拒绝
   └── 运行时约束检查（IP/时间/地域/session:max-concurrent）
7. 检查 capabilities                   ← 业务能力匹配（glob 通配：声明作模式覆盖要求，见 `RequiredCapabilities`）
8. 应用 Gateway Policy                 ← 运行时策略（超时/重试/限流/路由）
9. 允许/拒绝
```

**理由**：PA 约束和 AIC 约束是两层独立检查，分别作用于授权边界和执行边界，不存在子集关系。

## 多约束组合逻辑

当证书中包含多个 `authorizationConstraints` 时：

> 网关 **MUST** 要求所有约束同时满足（**AND 逻辑**）。任何一项约束不满足，则拒绝请求。

示例：

```json
{
  "authorizationConstraints": [
    {"schemeId": "constraint", "capabilityId": "time:window",
     "parameters": "{\"start\":\"22:00\",\"end\":\"06:00\"}"},
    {"schemeId": "constraint", "capabilityId": "network:cidr",
     "parameters": "[\"10.0.0.0/8\"]"}
  ]
}
```

→ 必须同时满足"夜班时间"**且**"内网 IP"才放行。

## 决策模型

```
AIC.capabilities: agent 的能力声明
AIC.authorizationConstraints: Agent 级授权边界约束（v1.6）
PrincipalAuthorization.grants: 主体允许授予的能力
PrincipalAuthorization.authorizationConstraints: 主体级授权边界约束（v1.6.1，独立于 AIC 约束）
T_policy: 网关本地策略

EffectiveCapability = P_grants ∩ C_agent ∩ T_policy
EffectiveConstraint = PA_constraints ∩ C_constraint ∩ T_constraint_policy

direct 模式（无 AIC）:  审计 actor = principal, 权限边界 = PA ∎ PA_constraints
authorized 模式（有 AIC）: 审计 actor = agentId, 权限边界 = C_agent ∩ PA_collected ∩ T_policy
representative 模式:    审计 actor = principalUid, 权限边界 = P ∩ C ∩ T
```

## 证书体积约束（v1.6）

| 证书类型 | 建议上限 | 硬上限 | 说明 |
|---------|---------|-------|------|
| 全协议安全上限 | 12KB | 16KB | 四网关全部兼容 |
| 握手证书 | 8KB | 16KB | 用于 mTLS 握手的 AIC 证书，超出 16KB 会导致 QUIC 握手失败 |
| 完整授权证书 | 64KB | 128KB | 含全部 capabilities + constraints + extensions，应用层传输 |
| 单条 Capability parameters | 512B | 4096B | 05-capability.md §Parameters |

超过硬上限的证书 MUST 被网关拒绝。

## 委托深度控制（FUTURE）

当证书扩展中包含 `DelegationDepthControl` 时：

| # | 检查 | 规则 |
|---|------|------|
| Φ1 | chainDepth ≤ maxDepth | `chainDepth` MUST ≤ `maxDepth`，超出则拒绝连接 |
| Φ2 | chainDepth 连续性 | 第 N 级 Agent 对下级授权时，自建 `chainDepth=当前值+1` |
| Φ3 | maxDepth 不变性 | 整条委托链中 `maxDepth` 由顶层 Principal 设定，下级不得篡改 |

> FUTURE：当前网关仅支持单层委托（chainDepth = 0），多级委托链的上述规则为规范预留。
