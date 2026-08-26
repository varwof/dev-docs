# Change Log

## Specification Changes (2026-08-12, v1.7.2, OID Tree Slimming)

| Change | Description |
|--------|-------------|
| OID tree slimming | AIC tree retains only three core items: AgentIdentity (.1.1.1), DelegationAuthorization (.1.1.2), DelegationDepthControl (.1.1.4, FUTURE); deleted AlgorithmSuite (.1.1.10, removed in v1.5 but not cleaned), TransparencyInfo (.1.1.12, CT uses 6.x or external standards) |
| MarketAccess consolidated to branch | Only retains `.3.1` MarketAccessId; removed AIC tree .1.1.4 MarketAccessLite residual (`OIDAICMarketAccess` constant removed) |
| Branch 3 cleanup | Deleted EUDIWallet placeholder (.3.4), branch 3 further planning TBD |
| Naming unified | `OIDAICUserAuth` → `OIDAICDelegationAuthorization` (.1.1.2) |
| isKnownExtension | Removed TransparencyInfo (.1.1.12); DDC OID constants added (.1.1.4 series, specification §3.7), extension parsing pending P1-11 delegation chain implementation wiring |

## Implementation Enhancements (2026-08-12, P1-13/14/15/16, Non-Specification Changes)

| Change | Description |
|--------|-------------|
| Plugin audit level differentiation (P1-13 / P2-A-28) | `gateway-core` `AuditEntry`/`PluginAuditEntry` adds `Level` field (JSON `level`): pipeline plugin rejection and execution error → WARN, allow → INFO; `LogPluginDecision` empty Level infers from Decision, backward compatible with old callers |
| Unknown constraint strict mode (P1-14 / P1-B-23) | `AdmissionConfig.StrictConstraints`/`PipelineConfig.StrictConstraints`: default off (unknown constraint audit warning + ignore, forward compatible); when enabled, AIC and PA two-level unknown constraint types fail-closed |
| Renewal threshold percentage-based (P1-15 / P2-A-11) | `NeedRenewPct` (default 10%, `DefaultRenewPct`) coexists with fixed 2min fallback (takes min); three gateways changed to `NeedRenewPct(cert,0)`; `NeedRenew` fixed window retained for compatibility |
| agent-proxy validity upper limit configurable (P1-16 / P1-B-09/25 / P2-A-04) | agent-proxy (authorized mode) certificate validity upper limit changed from hardcoded 1h to `SignConfig.MaxAgentProxyValidity` (`MaxAgentProxyValidityLimit()`, 0 → default 1h); config item `defaults.agent_proxy_max_validity` (default `1h`, ≤24h effective, exceeding ignored and falls back); injected in apiIssueCert / apiAICIssue / reissue three entry points |

## Implementation Enhancements (2026-08-12, P1-10 / P1-B-13, Non-Specification Changes)

| Change | Description |
|--------|-------------|
| DA timestamp freshness defense landed | CA issuance side (`POST /api/v1/certs` agent-proxy branch + `POST /api/v1/aic/issue`) adds `|now - timestamp| ≤ da_max_timestamp_skew` validation (default 30s, configurable, `"0"` disables); exceeding window rejects 403 `api.da_timestamp_stale`; together with nonce uniqueness forms the specification's "second line of defense in a short time window" (06-delegation-auth.md §Verification Flow (CA Issuance Phase) ①) |
| Gateway-side optional switch | `gateway-core` `AdmissionConfig` adds `CheckDAAge` (default false) / `DAAgeMax` (default 30s), `CheckDAFreshness` standalone helper; default off to maintain "lifecycle borne by NotAfter" design |

## Implementation Enhancements (2026-08-12, P1-A-12, Non-Specification Changes)

| Change | Description |
|--------|-------------|
| keyHash algorithm family landed | types `KeyHashFromSPKI` supports full SHA-2/SHA-3 family computation (SHA-256/384/512 + SHA3-256/384/512, 6 total); `MakePrincipalUidFromCertWithAlgo` adds algorithm parameter; `ValidatePrincipalUidKeyHash` validates by `hashAlgo` output length (32/48/64 bytes); SM3/BLAKE2/BLAKE3 zero-external-dependency policy registers OID+length mapping only, explicitly reports unsupported without silent degradation; core copy synchronized (`internal/ca/aic.go` delegates to types mapping table). `MakePrincipalUidFromCert` old signature retains default SHA-256 backward compatibility |

## Implementation Enhancements (2026-08-07, Non-Specification Changes)

| Change | Description |
|--------|-------------|
| Multi-level delegation chain landed | `gateway-core` adds `DelegationChainVerifier` / `VerifyDelegationChain`: reuses `DelegationAuthorization` structure (no new ASN.1 types/OIDs), bottom-up level-by-level verification + `chainDepth ≤ maxDepth` check; `aicverify chain` CLI recursive verification. `DelegationDepthControl` OID (.1.1.4) remains specification reserve, not used in implementation |

## v1.7 → v1.7.1 (2026-08-05)

| Change | Description |
|--------|-------------|
| New `Reason` type | `SEQUENCE { reasonCode UTF8String, description UTF8String }`, both `reasonCode` and `description` MUST be present and non-empty |
| Reason field naming | `code` → `reasonCode`, `display` → `description` (aligned with X.509 `reasonCode` convention); `reasonCode` is controlled vocabulary (SCREAMING_SNAKE) |
| `DelegationAuthTBS` adds `reason` | Required, positioned after principalUid, covered by principal signature |
| `DelegationAuthorization` adds `reason` | Same delegation reason as `DelegationAuthTBS.reason`, required, positioned at start of structure; `reason` **does not enter** `PrincipalAuthorization` |
| `reason` made required | Authorization must always have a reason: `Reason` in DA/TBS is a required field (not OPTIONAL), avoiding blank authorization |
| 03-validation adds Reason validation | Both `reasonCode` and `description` MUST be present (R1/R2), `reasonCode` recommended SCREAMING_SNAKE (R3), length limits `reasonCode`≤64 / `description`≤512 (R4/R5) |
| Encoding tag conventions | All OPTIONAL fields use context-specific `[n] EXPLICIT`, numbered starting from 0 in field order within structure; required fields keep universal tags (see 01-asn1.md §Encoding Tag Conventions) |
| Tag renumbering | AIC constraints `[0]`/extensions `[1]`; TBS constraints `[0]` (reason is required, no tag); DA has no OPTIONAL fields (reason is required, no tag); PA constraints `[0]`/delegationPolicy `[1]`/extensions `[2]`; DelegationPolicy maxSessionHours `[0]`; PrincipalUid hashAlgo `[0]`; Capability parameters `[0]` |
| `DelegationMode` type | `ENUMERATED` → `INTEGER (0..1)` (Go `encoding/asn1` native support, cross-language implementation consistent) |
| Security and integrity reinforcement | keyHash validation by hashAlgo output length (current SHA-256 = 32 bytes); capabilities and authorizationConstraints cannot both be empty; capabilities prohibit constraint schemeId |
| keyHash made algorithmic | `keyHash = hashAlgo(SPKI)`, length determined by algorithm (SIZE(1..64)); specification does not restrict algorithm set, current implementation SHA-256, SM3 etc. later extended via hashAlgo |
| Constraint schemeId whitelist | authorizationConstraints schemeId MUST ∈ {constraint, constraint-v1, varwof/constraint-v1}, other values rejected |
| Reason length limits | reasonCode SIZE(1..64), description SIZE(1..512), reasonCode should be as short as possible |
| DA required and dual certificate | delegationAuthorization is required; dual certificate: handshake cert and authorization cert are both complete AIC, both MUST carry DA |
| TBS SIZE unified | TBS and AIC field constraints consistent (agentId 1..256, capabilities 0..256, constraints 0..8) |
| requestedLifetime range | ASN.1 (1..86400), SHOULD 3600–86400 |
| Capability parameter subset validation clarified | `C_agent.parameters ⊆ P_grants.parameters` mechanically validated at CA issuance phase (capability layer, same level as capability-level subset); authorization constraint layer does not apply subset relationship (v1.6.1 preserved); 01-asn1 §Parameters intersection semantics adds execution layer note; 06 CA issuance validation adds parameter-level subset |
| Encoding and flow reinforcement | AIC/PA extensions MUST be non-critical; timestamp MUST be UTC; principal certificate chain/revocation verification responsibility clarified; signing algorithm set clarified (ECDSA-SHA256 / RSA-SHA256, Ed25519 MAY) |

## v1.6.1 → v1.7 (2026-07-30)

| Change | Description |
|--------|-------------|
| `signatureAlgo` → `signatureAlgorithm` | Aligned with X.509 RFC 5280 naming (algorithmIdentifier) |
| `signature` → `signatureValue` | Aligned with X.509 RFC 5280 naming (signatureValue) |
| DA field order confirmed | requestedLifetime → timestamp → nonce → signatureAlgorithm → signatureValue (algorithm-before-value) |
| 06-delegation-auth DA definition corrected | DA field order in 06-delegation-auth.md consistent with 01-asn1.md |
| 02-code-map / 06-delegation-auth / README references updated | All `signature`/`signatureAlgo` references unified to new names |

## v1.6 → v1.6.1 (2026-07-30)

| Change | Description |
|--------|-------------|
| PrincipalAuthorization adds `authorizationConstraints` | PA-level authorization boundary constraints, reusing Capability container (`schemeId` ∈ {`constraint`, `constraint-v1`, `varwof/constraint-v1`}) |
| PA/AIC constraints independently checked | PA constraints and AIC constraints independently checked at their respective semantic layers, with no subset relationship. PA constrains principal authorization boundary, AIC constrains Agent execution boundary |
| `CheckConstraintParameterBounds` deleted | Parameter boundary intersection validation semantic error: PA and AIC constraints at different layers, should not enforce subset relationship |
| 03-validation decision model updated | Added `PA.authorizationConstraints` entry |
| 07-capability plugin model | Clarified as JSON file configuration, not .so/external processes |
| 10-enterprise-profile | Added SPKI hash query API reference |
| 01-asn1 PA description updated | Field table clarifies PA constraints independent of AIC constraints |

## v1.5 → v1.6 (2026-07-30)

| Change | Description |
|--------|-------------|
| New `authorizationConstraints` field | AIC structure + DelegationAuthTBS |
| Constraints reuse Capability container | schemeId fixed as `"constraint"` |
| Three built-in constraint types | `allowed-cidr` / `max-concurrent` / `time-window` |
| Constraint count limit | ≤ 32 entries, single parameters ≤ 512 bytes |
| Gateway offline checking | Verified during TLS handshake phase, no external system dependency |
| Constraint parameter boundary validation | Agent-declared parameter values do not exceed principal (PrincipalAuthorization) authorization range |
| Unknown constraint forward compatibility | Default ignore + audit warning, `EnforceUnknownConstraints: true` enables strict rejection |
| Verification order fixed | Constraint checks take priority over capability checks (low-cost fast rejection) |
| DelegationAuthorization signature covers constraints | VerifyDelegationAuth TBS reconstruction includes authorizationConstraints |
| PrincipalAuthorization OID fix | `isKnownExtension` list `.1.5` → `.1.2` |
| PrincipalUid security policy | KeyHash change = new identity, existing certificates MUST be revoked |
| Parameters intersection semantics clarified | Agent parameters exceeding bounds = entire Capability invalid |
| Revocation online/offline modes | Online MUST OCSP/CRL, offline fail-open + high-risk audit |
| time-window enforces UTC | `timezone` field deprecated, display only |
| PrincipalUid string display only | Machine comparison etc. based on ASN.1 structure deserialization |
| GatewaySession gradually deprecated | HardTimeout/MaxRetries moved to gateway local policy configuration |
| Delegation depth control specification reserve | OID .1.1.4 (DelegationDepthControl), chainDepth/maxDepth field definitions, multi-level delegation chain architecture description. **Not yet implemented** |
| Certificate size limits clarified | 12KB safety limit covers all four gateways, 16KB QUIC hard limit, 256 caps entry limit |

## v1.4 → v1.5 (2026-07-20)

| Change | Description |
|--------|-------------|
| Deleted agentType | Agent autonomy level expressed implicitly by Capability |
| Deleted AlgorithmSuite | Algorithm negotiation follows RFC 5280/TLS 1.3 |
| Deleted SPIFFE-Compatibility | Optional Profile, not Core |
| Deleted approvalScope/approvedCapIds | Capability itself sufficiently expresses granularity |
| Deleted VendorRegistry (AIC child node) | Moved to `.1.4` independent branch |
| Deleted PrincipalAuthorization.roles | Authorization decisions must not depend on role labels |
| Deleted PrincipalAuthorization.externalRef | Uses extensions slot |
| Deleted OfflineRBAC standalone extension | Implemented by Capability Scheme |
| Deleted UserExtensions | Covered by built-in extensions slot |
| Deleted PrincipalProfile | Organizational attributes carried by directory service |
| ExecutionConstraint changed to Capability Scheme | No longer an independent X.509 extension |
| New Credential Bundle concept | Dual-credential offline verification model |
| OID tree restructured | Core retains only AIC, PrincipalAuthorization, Capability Registry |
| PrincipalUid.hashAlgo | Changed to AlgorithmIdentifier OPTIONAL, defaults to SHA-256 when omitted |
| DelegationPolicy | Adds version field |
| DelegationAuthorization adds nonce | Required 32 bytes anti-replay |
| DelegationAuthorization adds requestedLifetime | 3600-86400 seconds, default 3600 |

## v1.3 → v1.4 (2026-07-13)

| Change | Description |
|--------|-------------|
| DelegationAuthorization nonce anti-replay | 32-byte CSPRNG required |
| Offline Fail-Close clarified | Any verification failure = rejection |
| Capability count limit | 256 hard upper limit |
| Machine principal support note | realm segment can carry organization domain |
| representative certificate rotation constraint | keyHash unchanged = automatic continuation |
| GDPR right to be forgotten mitigation | principalUid uses UUID |
| OCSP Must-Staple requirement | Set at server certificate issuance |
| Certificate size constraint | Including all extensions ≤12KB |

## v1.2 → v1.3 (2026-07-13)

| Change | Description |
|--------|-------------|
| OID tree expansion | Chinese cryptography SM2/SM3/SM4 + CT |
| algorithmSuite activation | PQC algorithm suite OID placeholder |
| ExecutionConstraint keyDerivation | HKDF derivation parameters |
| signerCache caching | Decrypted signer in-memory cache |
| MemoryBuffer | Three persistence modes |
| Batch issuance API | 12 worker pool |

## v1.1 → v1.2 (2026-07-12)

| Change | Description |
|--------|-------------|
| OID clarification | principalUid format, PolicyRef/ExternalPolicyRef distinction |
| Policy priority adjudication | 5-level dynamic policy |
| migrating status | Renewal old certificates temporarily exempt from quota |
| admin disconnect API | Administrator proactive disconnect |
| Glob detailed rules | * / ** wildcard semantics |

## v1.0 → v1.1 (2026-07-12)

| Change | Description |
|--------|-------------|
| PrincipalAuthorization | User permission declaration extension |
| delegationMode | authorized / representative |
| approvalScope + approvedCapIds | Per-item signed approval |
| Cascading revocation | principalUid index |
| Audit WAL + traceId | Integrity guarantee |
| Capability glob matching | * / ** wildcards |
| v1 delegation restriction | Single-level Principal → Agent only |

## v1.0 (2026-07-10)

Initial finalization.
