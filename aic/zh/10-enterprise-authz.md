# 企业权限自治部署剖面

> 版本：v1.0
> 日期：2026-07-30
> 对应 AIC 规范 v1.6
> 状态：🟡 PA 结构 + authz.json 已实现；**FUTURE**：`group_to_role` 映射（§3.1）、LDAP provisioner（§3.3）、目录同步（§3.4）、状态→自动吊销（§3.2）

利用 AIC 规范中的 `PrincipalAuthorization` 扩展实现企业组织级权限自治，**不涉及 Agent 委托链**。将 PKI CA 层级映射为企业组织架构，每级负责人拥有本级 CA 管理权限，向下签发子 CA 或用户证书。

## 分层 CA 模型

```
Root CA（离线冷备）
  └── Policy CA（企业策略 CA，超级管理员掌管）
        ├── 财务部 CA（财务总监管理）
        │     ├── 财务员工 cert + PrincipalAuthorization
        │     └── ...
        ├── 研发部 CA（CTO 管理）
        │     ├── 研发员工 cert + PrincipalAuthorization
        │     └── ...
        └── 市场部 CA（市场总监管理）
              ├── 市场员工 cert + PrincipalAuthorization
              └── ...
```

| 层级 | CA | 管理者 | 职责 |
|------|----|--------|------|
| L0 | Root CA | 安全委员会 | 离线签发 Policy CA，冷备 |
| L1 | Policy CA | 超级管理员（企业负责人） | 创建/删除部门 CA，设定全组织策略基线 |
| L2 | 部门 CA | 部门负责人 | 为本部门员工签发证书，管理本部门权限 |
| L3 | 用户证书 | 员工本人 | 持有私钥，证书内含 PrincipalAuthorization |

### 管理流程

**超级管理员（Policy CA 管理者）：**
- `pki ca init --profile policy-ca --name <部门CA>` — 创建部门 CA（签发证书 + 设定 maxPathLen + 有效期）
- `pki ca revoke --serial <SERIAL>` — 吊销部门 CA（整个部门权限一键废止）
- 设定全组织策略基线：`authz.json` 中的角色定义、权限模板、CRL 周期

**部门负责人（部门 CA 管理者）：**
- `varwof-cli issue --ca 财务部-CA --profile user` — 签发员工证书
- `pki revoke --serial <SERIAL>` — 吊销员工证书（离职/权限变更）
- 通过 `PrincipalAuthorization` 为员工分配角色和权限

**员工：**
- 持有自己的密钥对（私钥从不在服务端生成或存储）
- 证书内含 `PrincipalAuthorization`，网关/应用层直接解析执行
- 不需要查外部权限系统，证书自带一切

## 权限结构

用户证书中的 `PrincipalAuthorization` 扩展承载权限信息：

```asn1
PrincipalAuthorization ::= SEQUENCE {
    version                     INTEGER DEFAULT 1,
    grants                      SEQUENCE OF Capability,
    authorizationConstraints    [0] EXPLICIT SEQUENCE SIZE(0..32) OF Capability OPTIONAL,
    delegationPolicy            [1] EXPLICIT DelegationPolicy OPTIONAL,
    extensions                  [2] EXPLICIT Extensions OPTIONAL
}
```

### 角色设计

角色在 `authz.json` 中定义，按部门隔离；证书 OU 通过 `ou_mapping` 映射到角色：

```json
{
  "roles": {
    "财务部/会计": {
      "grants": ["finance:query:invoice", "finance:report:monthly"],
      "profiles": ["finance-acc"]
    },
    "财务部/总监": {
      "grants": ["finance:*:*", "admin:finance-ca:*"],
      "profiles": ["finance-dir"]
    },
    "研发部/工程师": {
      "grants": ["code:read:repo", "code:pr:create"],
      "profiles": ["rd-eng"]
    },
    "研发部/CTO": {
      "grants": ["code:*:*", "admin:rd-ca:*"],
      "profiles": ["rd-cto"]
    },
    "超级管理员": {
      "grants": ["admin:*:*"],
      "profiles": ["m-superadmin"]
    }
  },
  "ou_mapping": {
    "FinanceAcc": "财务部/会计",
    "FinanceDir": "财务部/总监",
    "RDEngineer": "研发部/工程师",
    "RDCTO": "研发部/CTO",
    "SuperAdmin": "超级管理员"
  }
}
```

> **注意**：`authz.json` 中的角色是扁平定义（无继承），每个角色独立列出 `grants`。
> 签发时策略引擎将角色的 `grants` 写入 `PrincipalAuthorization`。
> 角色与证书 OU 的映射通过 `ou_mapping` 段实现。

### 权限粒度

通过 `Capability` 的 `schemeId:capabilityId:parameters` 三元组表达：

| 表达式 | 含义 |
|--------|------|
| `finance:query:invoice` | 财务部查询发票 |
| `finance:*:*` | 财务部全部操作 |
| `code:read:repo` | 代码只读 |
| `admin:finance-ca:issue` | 管理财务部 CA 的签发权 |
| `admin:*:*` | 全部管理权限 |

## 权限变更

### 场景：员工转岗

```
员工从 财务部/会计 → 研发部/工程师

审计痕迹：
  1. 财务总监吊销旧证书（crl 签发 + ocsp 立即生效）
  2. CTO 签发新证书（含新部门 PrincipalAuthorization）
  3. 旧证书添加到 CRL，新证书开始使用
```

时间线：

| 步骤 | 操作 | 时效 |
|------|------|------|
| T+0 | 财务总监 `pki revoke --serial <旧证书>` | CRL 下次发布后生效（默认 1h 内） |
| T+0 | CTO `pki issue --ca 研发部-CA --profile user` | 即时 |
| T+0 | 员工获取新证书 + 私钥 | 即时 |
| T+5min | CRL 刷新，旧证书全网失效 | CRL 缓存 TTL |

> OCSP 响应当即生效，推荐同时配置 OCSP + CRL 双保险。CRL 作为离线备用。

### 场景：临时任务

使用短命证书，有效期 ≤ 1h：

```bash
# 部门负责人签发短时证书（--validity 单位：天，0 表示默认）
varwof-cli issue --ca 研发部-CA \
  --profile user \
  --validity 1 \
  --cn "临时审计任务" \
  --pa '["audit:read:log", "audit:export:report"]'
```

任务完成后证书自动过期，无需吊销。匹配 `DelegationAuthorization.requestedLifetime` 机制。

### 场景：员工离职

1. 部门负责人吊销该员工所有证书（`pki revoke --principal-uid <uid>`）
2. CRL + OCSP 即刻或延时生效
3. 审计日志记录吊销操作及操作者

### 场景：员工降权（运行时 PA 刷新，即时生效）

主体吊销重签（**同一密钥对**、**更少的 grants**）后，旧 AIC 证书仍密码学有效
（`principalUid.keyHash` 不变），但权限应立即收缩。实现（gateway-core 运行时
PA 刷新）：

- `CheckAdmission` 在代表模式 P∩C 交集前，以主体**当前**证书（`UserCert` 或凭证包
  `Principal`，keyHash 交叉校验同一主体）的 `PrincipalAuthorization` 为权威
  P_grants；
- 旧 AIC 的越界能力被从 `EffectiveCaps` 剔除——**无需重签 agent 证书**，也无需等待
  CRL/OCSP 传播（凭证包/解析器拿到新证书即生效）；
- 吊销路径：core CLI `revoke` / API `POST /api/v1/cert/{ca}/{serial}/revoke`
  （支持按 PrincipalUid 级联）/ client `revoke`；级联吊销是更强的机制（agent
  证书直接吊销），PA 刷新是"证书还在、权限收缩"机制，两者互补。
- 验证：`TestPrincipalDowngradeRevokesAgentPermissions`（C1→C2 同密钥、少一个权限 →
  旧 AIC 的 INSERT 从 EffectiveCaps 消失）。

### 辅助工具：按公钥查询证书

通过 SPKI 哈希（当前实现 SHA-256）查找同一密钥对的所有证书：

- **API**: `GET /api/v1/cert/by-key?hash=<hex>`
- **CLI**: `client find-by-key --key <path>` / `--cert <path>` / `--hash <hex>`
- **用途**：员工换证时识别同一密钥对的旧证书、排查重复签发、吊销前枚举关联证书

参见 `dev-docs/api/core.md` §Certificate Retrieval。

## 与 Agent 委托的关系

本剖面**完全独立**于 AIC 的 Agent 委托功能：

| 维度 | 企业权限自治 | Agent 委托 |
|------|-------------|------------|
| 证书持有者 | 企业员工（自然人） | AI Agent / 自动化程序 |
| 权限载体 | `PrincipalAuthorization` | `AIC.capabilities` + `DelegationAuthorization` |
| 授权模式 | 直属 CA 签发 | Principal 签名委托 |
| 多级 | 组织 CA 层级 | 委托链（FUTURE） |
| 可选性 | 所有用户证书均包含 | 仅 Agent 证书需要 |

两者可同时部署在同一套 PKI 中。员工证书走企业权限自治，Agent 证书走委托授权。同一套 Root CA 和 Policy CA，不同的 profile。

```
Root CA
  └── Policy CA
        ├── 财务部 CA ──── 财务员工证书（企业权限自治）
        ├── 研发部 CA ──── 研发员工证书（企业权限自治）
        └── Agent CA ──── Agent 证书（委托授权）
```

## 安全建议

1. **部门 CA 生命周期**：部门 CA 证书有效期建议 2-5 年，到期前 30 天自动提醒续期
2. **用户证书有效期**：默认 7-30 天（短命证书降低吊销压力），上限 90 天
3. **吊销时效**：OCSP 建议 5 分钟缓存，CRL 每日发布；**高安全场景** OCSP must-staple
4. **超级管理员权限分离**：Policy CA 私钥加密 + systemd credential 注入 + 持卡人审批双人操作
5. **审计**：所有签发/吊销操作记录审计日志，TSA 时间戳签名保证不可篡改
6. **密钥归属**：员工证书私钥 MUST 在客户端生成，CA 不接触私钥明文
