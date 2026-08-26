# Capability 规范

> 版本：v1.0
> 状态：核心规范
> 关联：`01-asn1.md`（ASN.1 结构定义）

Capability 是 Varwof PKI 体系中**协议化的权限容器**。Core 只定义结构和匹配规则，不定义任何具体能力语义。能力方案由 `schemeId` 标识，网关按 `schemeId` 路由到对应插件执行决策。

## 字符串表示格式

### 完整格式（canonical）

```
{schemeId}:{capabilityId}
```

示例：
- `varwof-gateway-v1:http:GET:/api/v1/users`
- `mysql:SELECT:*`
- `aws-bedrock-v2:invoke-model`

### 简写格式（shorthand）

当 `schemeId` 可推断时允许省略：
- `http:GET:/api/v1/users`（隐含 `varwof-gateway-v1` 或上下文默认方案）
- `SELECT:*`（隐含默认数据库方案）

## Parameters 编码

Parameters 以 JSON 格式嵌入 ASN.1 OCTET STRING：

```json
{
  "max_rows": 1000,
  "timeout_ms": 5000,
  "rate_limit": {"rps": 100, "burst": 50},
  "denied_columns": ["password_hash", "ssn"]
}
```

### JSON Schema 约束

- 顶层必须是 JSON 对象（`{}`）或数组（`[]`）
- 数组元素类型：`string`、`number`、`boolean`、`object`、`null`
- 键名：`^[a-zA-Z_][a-zA-Z0-9_]*$`
- 值类型：`string`、`number`、`boolean`、`array`、`object`、`null`
- 嵌套深度：最多 8 层
- 总大小 ≤ 4096 字节（UTF-8 编码后）

### 标准字段（推荐）

| 字段 | 类型 | 说明 |
|------|------|------|
| `max_rows` | integer | 最大返回行数 |
| `timeout_ms` | integer | 超时时间（毫秒） |
| `rate_limit` | object | 速率限制 `{"rps":100,"burst":50}` |
| `denied_columns` | array | 禁止访问的列 |
| `allowed_columns` | array | 允许访问的列 |
| `cache_ttl` | integer | 缓存 TTL（秒） |
| `require_approval` | boolean | 是否需要审批 |
| `audit_level` | string | 审计级别（`full` / `summary`） |

## Glob 匹配规则

### 通配符定义

| 通配符 | 含义 | 匹配范围 | 示例 |
|--------|------|---------|------|
| `*` | 匹配一个路径段 | 不含 `/` 的任意字符 | `http:GET:/api/v1/*` → `GET /api/v1/users` |
| `**` | 匹配跨路径任意深度 | 包含 `/` | `http:GET:/api/v1/**` → `GET /api/v1/users/roles` |
| `{a,b}` | 选择匹配（**FUTURE，未实现**） | `a` 或 `b` | `http:{GET,POST}:/api/*` |
| `[a-z]` | 字符类匹配 | 范围内字符 | `http:[A-Z]*:/api/*` |

### 详细规则

1. **`*` 匹配一个路径段**（不含 `/`）
   - `http:GET:/api/v1/*` 匹配 `GET /api/v1/users`
   - 不匹配 `GET /api/v1/users/roles`

2. **`**` 匹配跨路径任意深度**
   - `http:GET:/api/v1/**` 匹配 `GET /api/v1/users`、`GET /api/v1/users/roles`
   - `http:**` 匹配该方案下任意能力

3. **`*` 可匹配空字符串**
   - `http:GET:/api/*/v1` 匹配 `GET /api//v1`

4. **`{a,b}` 选择匹配**
   - `http:{GET,POST}:/api/*` 匹配 `GET` 或 `POST`

5. **`[a-z]` 字符类匹配**
   - `http:[a-z]*:/api/*` 匹配小写方法

### 匹配优先级

多条规则匹配时，**最精确的规则优先**：

1. 精确匹配：`http:GET:/api/v1/users`
2. 单段通配（`*`）：`http:GET:/api/v1/*`
3. 多段通配（`**`）：`http:GET:/api/v1/**`
4. 选择通配（`{a,b}`）：`http:{GET,POST}:/api/*`
5. 字符类通配（`[a-z]`）：`http:[a-z]*:/api/*`
6. 方案级通配（`*`）：`http:*:*`

## 内置能力方案定义

### `varwof-gateway-v1` — 网关能力

```
http:GET|POST|PUT|DELETE   HTTP 方法
tcp:tunnel|stream          TCP 模式
udp:plain|dtls|quic        UDP 模式
admin:metrics|audit|policy  管理能力
```

### `mysql-v1` — 数据库能力

```
SELECT  查询
INSERT  插入
UPDATE  更新
DELETE  删除
```

### `varwof/constraint-v1` — 授权边界约束（v1.6，按 03-validation 统一）

```
network:cidr         允许的 IP 网段
session:max-concurrent  最大并发 Agent 实例数
time:window          允许执行的时间窗口
geo-fence            地理围栏（IP→地域）
```

约束是授权方（主体）授予的**边界条件**，不是运行时策略：
- 由授权方决定、因人而异、变更频率低
- 网关在 TLS 握手阶段离线验证
- 不列入的典型：超时时间、重试次数、限流阈值、后端路由、日志级别

参见 `01-asn1.md` §authorizationConstraints 和 `03-validation.md` §authorizationConstraints 校验。

### 约束类型注册机制

`authorizationConstraints` 复用 Capability 容器（`schemeId` MUST 为 `"varwof/constraint-v1"`，其他值拒绝；兼容旧值 `"constraint"`/`"constraint-v1"`），新增约束类型需经过注册：

```
约束类型注册条目：
{
  "capabilityId": "device-binding",
  "parameters": {
    "type": "object",
    "properties": {
      "deviceId": { "type": "string", "maxLength": 64 },
      "tpmHash":  { "type": "string", "maxLength": 64 }
    },
    "required": ["deviceId"]
  },
  "description": "绑定到指定设备，仅允许从该设备发起连接",
  "gateway_plugin": "constraint-device-binding"
}
```

注册字段：

| 字段 | 说明 |
|------|------|
| `capabilityId` | 约束标识符，全局唯一 |
| `parameters` | JSON Schema 定义参数格式 |
| `description` | 约束的语义说明 |
| `gateway_plugin` | 网关插件名称，负责运行时检查 |

约束类型注册到 `Capability Scheme Registry`（`dev-docs/aic/` 或 `dev-docs/gateway/`）。网关在部署时加载对应约束插件。未注册的约束类型默认被网关**忽略**（记录审计告警，不阻断业务，确保向前兼容），严格模式由 `StrictConstraints: true` 配置开启。

### 插件部署模型

插件由网关配置中的 **`capability_plugins` JSON 字段**定义（非 .so/外部进程），内置四种类型：

| 插件类型 | 说明 | 配置方式 |
|---------|------|---------|
| `allowlist` | 白名单匹配，拒绝不在列表中的 schemeId | JSON 数组 |
| `denylist` | 黑名单匹配，拒绝列表中的 schemeId | JSON 数组 |
| `rbac` | 基于证书 OU 的角色权限检查 | JSON 角色→能力映射 |
| `webhook` | HTTP 回调，将决策委托给外部服务 | JSON URL + 超时 |

参见 `dev-docs/gateway/arch/gateway-architecture.md` §Capability Plugin Engine 和 `gateway-core/pluginconfig.go`。

## 安全考虑

- **长度限制**：`schemeId` ≤ 128 字节，`capabilityId` ≤ 256 字节，`parameters` ≤ 4096 字节
- **DoS 防护**：单个 AIC 中 Capability 条目数 ≤ 256
- **Glob 复杂度**：`**` 匹配 O(n)，n 为目标路径段数
- **Fail-Closed（约束层）**：未知约束类型（`constraint` scheme 下）默认审计告警+忽略，`StrictConstraints: true` 时拒绝；未知 schemeId 的业务能力默认跳过插件检查（审计 skip），不阻断
- **参数验证**：JSON 格式、键名、嵌套深度、总大小

## 向后兼容

- 无 `parameters` 字段 → 行为完全不变
- 旧格式 `capabilityId` 精确匹配继续支持
- 新增 `[a-z]` 语法为可选功能；`{a,b}` 交替匹配为 FUTURE（当前未实现）
