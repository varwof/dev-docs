# 双证书部署方案：握手证书 + 授权证书

> 版本：v1.1（2026-08-16，G4 强绑定）
> 状态：FUTURE — 部署策略设计稿（`VerifyBelongTo` 已实现，网关数据面接线未实现）

## 背景

AIC 证书可能承载大量 Capability（数十至上百条）和 AuthorizationConstraints（多 IP/地域/时间窗），证书体积可能从几 KB 膨胀到几十 KB。

QUIC 协议对 TLS 握手阶段的证书链有 ~16KB 的硬性限制。超过该值握手直接失败。

## 方案：一张证书拆两张

保持 AIC 协议不变，仅拆分证书内容到两张证书，在不同阶段出示：

| 证书 | 出示时机 | 内容 | 典型体积 |
|------|---------|------|---------|
| **握手证书** | mTLS/DTLS/QUIC 握手 | `agentId` + `principalUid` + `delegationMode` + `DelegationAuthorization`（capabilities 至少一条，具体占位能力由部署按注册表定义；authorizationConstraints 可空） | ~2-4KB |
| **授权证书** | TLS 握手完成后，应用层发送 | 完整 AIC：`capabilities` + `authorizationConstraints` + `DelegationAuthorization` + 扩展信息 | 可能 20-50KB |

### 执行流程

```
Agent                                    Gateway
  │                                          
  │ ① 握手证书 (agentId + principalUid + DA) 
  │──────────────────────────────────────────▶  TLS 握手（<16KB ✅）
  │                                          ② 验证握手证书链
  │                                          建立安全连接
  │
  │ ③ 应用层发送授权证书 (完整 AIC，含 DA)  
  │──────────────────────────────────────────▶  应用层（无体积限制 ✅）
  │                                          ④ 验证授权证书（同信任链）
  │                                            提取 capabilities + constraints
  │                                            执行授权决策
  │ ⑤ 业务数据                               
  │◀────────────────────────────────────────▶
```

### 为什么能绕过 QUIC 16KB 限制

QUIC 的 16KB 限制仅针对 **TLS 握手过程中的 Certificate 消息**。应用层（QUIC stream）发送的数据不受此限制。将授权证书放在握手完成后发送，完全绕开该硬性限制。

## Credential Bundle 整合

双证书方案天然适配 Credential Bundle 概念：

```
Credential Bundle
├── 握手证书 (Handshake Cert)    — 身份证明，TLS 层
├── 授权证书 (Authorization Cert) — 权限清单，应用层
└── CA Chain                     — 信任链
```

两个证书由 **同一 CA 签发**，信任链一致，验证逻辑不变。

## 授权证书的三种传递方式

### 方式 A：Agent 主动推送（推荐）

```
Agent → Gateway: 握手证书 (mTLS)
Agent → Gateway: 授权证书 (应用层 header/frame)
```

- 握手完成后，Agent 立即在应用层发送授权证书
- 网关缓存授权证书供后续请求使用
- 延迟最低，一次交互完成

### 方式 B：网关按需拉取

```
Agent → Gateway: 握手证书 (mTLS)
Gateway → pki-core: GET /api/v1/cert/by-key?hash=<agent-spki>
pki-core → Gateway: 授权证书
```

- Agent 只需发送握手证书
- 网关根据握手证书的 SPKI hash 从 pki-core 获取完整授权
- 适用场景：Agent 极简部署，不想携带大证书

### 方式 C：懒加载（按需拉取）

```
Agent → Gateway: 握手证书 (mTLS)
Agent → Gateway: 发送业务请求
Gateway: 发现缺少授权证书 → 向 Agent 索取
Agent → Gateway: 授权证书
```

- 网关只在需要时才请求授权证书
- 适用于一次性操作（如令牌交换）

## 网关处理逻辑

```go
func handleQUICConnection(conn quic.Connection, handshakeCert *x509.Certificate) error {
    // 1. 验证握手证书（TLS 层已完成）
    aic := parseAIC(handshakeCert)

    // 2. 接收授权证书（应用层）
    authCert, err := receiveAuthorizationCert(conn)
    if err != nil {
        return fmt.Errorf("auth cert required: %w", err)
    }

    // 3. 验证授权证书链（同一 CA）
    if err := verifyCertChain(authCert, trustedCAs); err != nil {
        return fmt.Errorf("auth cert chain: %w", err)
    }

    // 4. 验证 belong-to：握手证书和授权证书强绑定属于同一 Agent（G4）
    //    强绑定 = 同一密钥对（SPKI 逐字节相等，密码学绑定）
    //            + 同一 CA（同签发者）+ 同一信任链（授权证书可被
    //              验证握手证书链的同一信任根池验证）
    //    agentId 等标识字段仅用于日志，不参与绑定判定（UTF8String
    //    非密码学绑定，可被伪造，见 08-dual-cert.md 安全考虑）。
    if err := gw.VerifyBelongTo(handshakeCert, authCert, trustedCAs); err != nil {
        return fmt.Errorf("auth cert does not belong to handshake cert: %w", err)
    }

    // 5. 执行授权决策
    authAIC := parseAIC(authCert)
    return enforcePolicy(authAIC)
}
```

## 收益

| 维度 | 单证书 | 双证书 |
|------|--------|--------|
| mTLS 握手负担 | 全部证书一次传输 | 握手证书轻量（~2-4KB） |
| QUIC 兼容性 | 超 16KB 握手失败 | ✅ 握手证书始终小于 16KB |
| 授权证书更新 | 需重新握手 | 应用层更新，不断开 TLS |
| 部分授权变更 | 全部重签 | 只签授权证书 |
| 弱网适应性 | 大证书传输卡顿 | 握手证书极小，快速建立连接 |

## 安全考虑

| 风险 | 缓解措施 |
|------|---------|
| Agent 发送过期的授权证书 | 网关验证有效期 + CRL/OCSP |
| Agent 发送他人的授权证书 | **belong-to 强绑定（G4）**：同一密钥对（SPKI 逐字节相等）+ 同一 CA + 同一信任根池链验证；agentId 仅日志用，不作为绑定依据 |
| 网关未收到授权证书 | **强制 fail-close（G5）**：缺授权证书 = 拒绝。仅当连接对端证书本身即授权主体（agent==user 自授权，cert SPKI == KeyHash）时允许用对端证书验签；否则返回 `user_auth: authorization certificate required but not provided`。不提供"可选（降级）"配置项 |

> **G4 修复（2026-08-16）**：早期设计"握手证书.agentId == 授权证书.agentId
> **或** SPKI 相等"为弱绑定——agentId 是 UTF8String 非密码学绑定，攻击者用
> 他人 agentId 签发自己的授权证书即可通过"相同 agentId"分支 = 身份伪造。
> 现强制 **SPKI 强绑定（同一密钥对）+ 同 CA + 同信任链**（`pki-gateway-lib/belongto.go`
> `VerifyBelongTo`），agentId 仅日志用。双证书仍同 CA 签发，验证逻辑不变。

## 与单一证书的关系

双证书是 **部署策略优化**，不是对 AIC 协议的重定义：

- 两张证书使用**完全相同的 ASN.1 结构**（`AIC` 类型）
- `delegationAuthorization` 为必填字段，两张证书均 MUST 携带（授权证书可与握手证书使用同一 DA）
- 握手证书的 `capabilities` 至少包含一条（AIC 校验要求 capabilities 非空；具体占位能力由部署按注册表定义）；`authorizationConstraints` 可空（空 = 不限制）
- 如果需要，完全可以退回单证书模式（不拆分）
- 两者编码相同，仅在部署方式上拆分

## 总结

| 问题 | 答案 |
|------|------|
| QUIC 16KB 限制能绕过吗？ | ✅ 能，通过握手后再传授权证书 |
| 需要修改 AIC 协议吗？ | ❌ 不需要，部署策略调整即可 |
| 和 Credential Bundle 一致吗？ | ✅ 完全一致 |
| 推荐哪种传递方式？ | 方式 A（Agent 主动推送），延迟最低 |
