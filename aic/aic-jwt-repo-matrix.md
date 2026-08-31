# AIC-JWT 仓库支持矩阵（2026-08-31）

> 盘点各仓库对 AIC-JWT（draft-wei-aic-jwt-00）的支持现状与待办。
> 目标：**一个信任根、双载体（x509 AIC 证书 + AIC-JWT）共存互验**，agent 生态（尤其 TS/LLM）可简单接入。

## 角色划分

| 角色 | 说明 | 承担仓库 |
|---|---|---|
| 协议引擎 | AIC-JWT 核心（claims/JWS/11 步校验/keyhash/PA-DA） | `types`（Go）、`aic-jwt/ts/aicjwt.ts`（TS） |
| 签发 + AS | 签发 AIC-JWT、OAuth token 端点 | `core` |
| RS 校验方 | 校验 Bearer AIC-JWT、capability 判定 | `core`、`gateway`、`demo` |
| 出示 SDK | agent 运行时获取/携带 AIC-JWT | `aic-lib-java`、`aic-lib-dotnet`、`@varwof/agent`(TS,待建) |
| 签发侧 CLI | 签发 x509 AIC 证书（长期信任根身份） | `client` |

## 已完成

| 仓库 | 角色 | 支持内容 |
|---|---|---|
| `types` | 引擎 | claims/JWS sign/verify/11 步校验、keyhash、PA/DA、CapToPKI/PKIToCap；`certjwk.go`（CertToJWK/JWKS/AlgForPublicKey） |
| `core` | AS+RS | L0 JWKS（`/.well-known/jwks.json`，kid=CA SPKI hash）；L1 `ca.SignJWT`（复用 x509 签发全部校验）；L2 Bearer 校验（`provisioner/aicjwt.go`，kid→CA JWKS，capabilities 汇入 RBAC，双载体 mTLS vs cnf.jkt 一致性）；L3 `/oauth/token`（R8693 x509→JWT 兑换、R7523 JWT-bearer、R9068 access token、DPoP/mTLS PoP）；L4 e2e 矩阵（ES256/RS256/EdDSA） |
| `aic-jwt` | 参考实现 | Go 参考层 `oauth.go`（Issuer/ResourceServer/DPoP/token-exchange）+ **TS 核心 `ts/aicjwt.ts`（999 行，WebCrypto，浏览器/Node 兼容，含 542 行测试）** + browser demo |
| `aic-lib-java` | 出示 SDK | `com.varwof.aic.jwt`：Jws/Claims/Constraints/JwtJson/KeyHash/NonceStore/Validator/CapMatch |
| `aic-lib-dotnet` | 出示 SDK | `Varwof.Aic` 命名空间（对应 jwt 能力） |

## 还需要支持（按优先级）

| # | 仓库 | 角色 | 待办 |
|---|---|---|---|
| 1 | `gateway` / `gateway-core` | RS 校验方 | ✅ **已完成（2026-08-31）**：`gateway-core` 新增 `JWTVerifier`/`VerifyBearer`/`SynthesizeCertFromJWT`（`jwt.go`），kid→信任根 CA（`LoadJWTVerifier`），合成证书承载 AIC 喂现有 `RunAccessPipeline`；`gateway/http` `handleRequest` 增加 Bearer 分支（mTLS 优先，无证书才看 Bearer），信任根由 `tls.jwt_ca_file` 配置，4 个集成测试绿。待办：TCP/UDP 监听器暂仍仅 mTLS（按设计）；gateway-core 升级 types 到 v0.4.0 后打 tag 推送，移除 gateway go.mod 的本地 replace |
| 2 | `demo`（mysql-api / sqlite） | RS 示例 | 用 `types/aicjwt` 校验 Bearer + capability 匹配（如 `SELECT:*` 才放行），成为官方 TS agent 对接样例 |
| 3 | `@varwof/agent`（**新建**） | TS 出示 SDK | ✅ **已完成（2026-09-01）**：独立仓库 `github.com/varwof/agent`，vendored `aic-jwt/ts/aicjwt.ts`，`Agent.new()→authenticate()→fetch()/call()`，DPoP PoP 绑定（RFC 9449）、PKCE、scope/capability 请求、ES256/RS256/EdDSA；Node 22 strip-types 直接消费源码，5 单测绿，npm 打包验证通过 |
| 4 | `client`（可选） | 签发侧 | ✅ **已完成（2026-08-31）**：新增 `aic jwt` 子命令（RFC 8693 x509→AIC-JWT 兑换），`--cert`/`--scope`/`--out`/`--json`，输出可直供 gateway Bearer 鉴权；5 个单测绿 |

## 明确不需要

- `console`（web 管理 UI，走 operator/会话登录，不承载 AIC-JWT）
- `openaic`（openssl/lib 集成）、`bridge-ldap` / `bridge-oauth`、`pkcs7` / `crypto` / `protocols`
- `emilia-protocol`（AI agent 协议；未来若用 AIC-JWT 做身份再接入，前瞻）
- `client` 不需原生签发 JWT（AIC-JWT 是派生短效凭据，由 AS 兑换）

## 待定方向（未拍板）

- TS SDK（`@varwof/agent`）仓库位置：独立仓库（与 sdk-go 对称）/ aic-jwt 内 / core 内
- agent 认证主路径：Bearer AIC-JWT 兑换（推荐，浏览器/Serverless 友好） / 仅 mTLS 直通 / 两者
- 是否做 LLM 框架适配层（LangChain tool / OpenAI function-call 包装）
