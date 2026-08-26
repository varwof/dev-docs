# 编解码示例

## ParseAIC 用法

```go
cert, _ := x509.ParseCertificate(certDER)
aic, err := gw.ParseAIC(cert)
if err != nil {
    // unmarshal 失败
}
if aic != nil {
    fmt.Printf("Agent: %s, Principal: %s\n", aic.AgentId, aic.Principal())
    fmt.Printf("DelegationMode: %d\n", aic.DelegationMode)
    for _, cap := range aic.Capabilities {
        fmt.Printf("  Cap: %s / %s\n", cap.SchemeId, cap.CapabilityId)
    }
}
```

## ValidateAIC

```go
aic, _ := gw.ParseAIC(cert)
if err := gw.ValidateAIC(aic); err != nil {
    return nil, fmt.Errorf("aic validation failed: %w", err)
}
```

## IntersectPermissions（权限交集）

```go
intersection := aic.IntersectPermissions(principalAuth)
// intersection 为 capabilities 与 grants 的 CapabilityId 交集
```

## RunAccessPipeline（完整准入）

```go
result := gw.RunAccessPipeline(cert, gw.AdmissionConfig{
    RequireAIC:       true,
    RequireUserAuth:  true,
    DisallowRepresentative: true,
    NonceCache:       nonceCache,
    EnforceCapSizeConstraints: true,
    EnforceConstraints:      true,  // v1.6 强制执行 authorizationConstraints
})
if result.Decision != gw.DecisionAllow {
    return fmt.Errorf("access denied: %s", result.Reason)
}
```

## authorizationConstraints 示例（v1.6）

### 签发含约束的 AIC 证书

```json
{
  "agent_id": "deploy-agent-007",
  "principal_uid": "corp.com:zhangsan:dBjft...",
  "capabilities": [
    {"scheme_id": "mysql-v1", "capability_id": "SELECT:*"}
  ],
  "authorization_constraints": [
    {"scheme_id": "varwof/constraint-v1", "capability_id": "network:cidr",
     "parameters": "[\"10.0.0.0/8\", \"192.168.0.0/16\"]"},
    {"scheme_id": "varwof/constraint-v1", "capability_id": "session:max-concurrent",
     "parameters": "{\"max\": 3}"},
    {"scheme_id": "varwof/constraint-v1", "capability_id": "time:window",
     "parameters": "{\"start\": \"22:00\", \"end\": \"06:00\"}"}
  ]
}
```

### 网关运行时检查

```
约束类型        检查时机               检查逻辑
─────────────  ─────────────────────  ──────────────────────────
network:cidr            TLS 握手完成时         对端 IP ∈ 任一 CIDR
session:max-concurrent  新连接建立时            该 agent 连接数 < max
time:window             每次请求/包             当前 UTC 时间在窗口内
```

## PrincipalUid 通信格式

```text
corp.com:zhangsan:dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  realm    identifier               keyFingerprint (base64url)
```

```go
pu := gw.PrincipalUid{
    Realm: "corp.com",
    Identifier: "zhangsan",
    KeyHash: sha256Hash,
}
fmt.Println(pu.String())
// → "corp.com:zhangsan:dBjft..."

parsed, err := gw.ParsePrincipalUid("corp.com:zhangsan:dBjft...")
```

> **注意**：`PrincipalUid.String()` 产生的 `realm:identifier:keyFingerprint` 格式**仅供人类阅读和日志输出**。机器解析与判等 MUST 基于 ASN.1 结构体反序列化（`ParsePrincipalUid`），严禁将字符串分割结果用于安全决策。若 `realm` 或 `identifier` 内部可能包含冒号，调用方应使用 ASN.1 DER 封装传输。`ParsePrincipalUid` 仅在展示场景使用。按主体检索/关联（级联吊销、审计、证书查询）可通过数据库索引或 `realm` / `identifier` 字段完成，授权绑定仍以 keyHash 为准。

## DelegationAuthorization 签发与验证

参见 `06-delegation-auth.md`。

## Capability 匹配

```go
// 精确匹配
aic.CheckPermission("http:GET:/api/v1/users")

// glob 匹配
matchCapability("http:GET:/api/v1/users", "http:GET:/api/v1/*") // true
matchCapability("http:GET:/api/v1/users/roles", "http:GET:/api/v1/**") // true
matchCapability("http:POST:/api/v1/data", "http:POST:/api/v1/**") // true
```
