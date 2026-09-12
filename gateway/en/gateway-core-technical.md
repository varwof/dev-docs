# gateway-core — Shared Security Engine (Technical Reference)

**Module**: `github.com/varwof/gateway-core` (package `gw`)  
**Version note**: The local checkout at `~/src/github.com/gateway-core` is the source tree (`Version` default `"0.1.0"` in `version.go:8`, overridable via `-ldflags`). The `gateway` module pins `github.com/varwof/gateway-core v0.4.5` in `go.mod:8`; line references below for gateway-core were taken against this checkout. Where a line number is sensitive to the pinned version it is flagged.

This document describes, for each subsystem, its **mechanism** (what it does), **implementation** (where and how), **limitations** (known bounds), and **defects / risk notes** (security-sensitive behaviors). All citations are `file.go:line`.

---

## 1. Admission / Decision Pipeline

### Mechanism
`RunAccessPipeline` is the single, protocol-agnostic admission gate. Every data-plane connection/request across all three binaries (TCP, DTLS, QUIC, HTTP) funnels through it. It evaluates, in order: CRL revocation, OCSP status, RBAC roles, AIC/SPIFFE identity, capability/plugin requirements, nonce anti-replay, and authorization constraints, and returns a single `AdmissionResult` with `Granted`/`DenyReason`/`Principal`.

### Implementation
- `RunAccessPipeline` — `pipeline.go:105` (pipeline entry; in pinned v0.4.5 it is the orchestration at `pipeline.go:161`).
- `PipelineConfig` — `pipeline.go:55` (all inputs: checks, scope, identity, capability, audit, nonce, risk components).
- `AdmissionResult` — `decision.go:39`; `DecisionResult` — `decision.go:25`; `AdmissionConfig` — `decision.go:57`.
- `PipelineCheck` — `pipeline.go:29`.
- The pipeline result is consumed by the callers to drive `X-Client-Cert-*` header injection, per-cert connection accounting, revoker registration, and audit.

### Limitations
- The whole admission check is a single synchronous call; there is no retry, circuit-breaker, or async re-evaluation.
- Plugin evaluation inside the pipeline performs synchronous HTTP calls with a default timeout; there is no per-plugin context cancellation exposed at pipeline level.

### Defects / risk notes
- Wildcard role `RoleWildcard` (`*`, `rbac.go:23`) and wildcard capability `*` (`rbac.go:148`) match everything; callers must ensure such roles are never materialized onto untrusted principals.
- Pipeline is only as strong as its inputs — callers must supply CRL/OCSP caches; a nil cache skips that check silently.

---

## 2. Constraints / Parameter Validation

### Mechanism
Fine-grained post-authentication checks: CIDR source allow/deny, time-window allow, and custom per-parameter validators. Used to enforce authorization constraints on long-lived or request-bound operations.

### Implementation
- `ConstraintEvaluator` interface — `constraints.go:44`; `ConstraintRegistry` — `constraints.go:56`; `NewConstraintRegistry` — `constraints.go:66`; `Register` — `constraints.go:75`; `Evaluate` — `constraints.go:92`.
- `CIDRConstraintEvaluator` — `constraints.go:134` (`Evaluate` `constraints.go:154`).
- `TimeWindowConstraintEvaluator` — `constraints.go:187` (`Evaluate` `constraints.go:206`).
- `ParameterValidator` — `parameters.go:26`; `ParameterValidatorRegistry` — `parameters.go:36`; capability registry global — `capregistry.go:18`, `SetGlobalCapabilityRegistry` — `capregistry.go:33`.

### Limitations
- `CIDRConstraintEvaluator` only handles IPv4 (`net.ParseCIDR` + IPv4 mask); IPv6 CIDRs are silently rejected.
- `ConstraintRegistry.Evaluate` short-circuits on the first failure (no all-errors mode).

### Defects / risk notes
- Because the global capability registry is package-level, a mis-configured or mis-typed global can affect all listeners in a process. The gateways only assign it when `CapabilitySchemes` is configured (opt-in, fail-closed otherwise).
- **FIXED (2026-09-03): reload-removal staleness.** The gateways' `loadCapabilityRegistry` now clears the global registry (`SetGlobalCapabilityRegistry(nil)`) when `CapabilitySchemes` is unset on reload, so removing capability validation actually takes effect (previously a stale registry stayed active). The underlying structural fact remains: the global `CapabilityRegistry` is held in a package-level `atomic.Value` (`capregistry.go:33`) with no shutdown path.

---

## 3. RBAC / Authorization

### Mechanism
Offline (X.509-derived) role extraction and role/capability matching. Roles are read from certificate OIDs; there is no online directory integration.

### Implementation
- Role constants `RolePrefix`/`RoleAdmin`/`RoleAudit`/`RoleDeploy`/`RoleRead`/`RoleWrite`/`RoleDelete`/`RoleOps`/`RoleWildcard` — `rbac.go:13-23`.
- `OfflineRBAC` — `rbac.go:31`; `NewOfflineRBAC` — `rbac.go:49`; `ExtractRoles` — `rbac.go:68`; `CheckRole` — `rbac.go:115`; `HasRequiredCapability` — `rbac.go:148`.

### Limitations / defects
- No online/LDAP/OIDC; roles are frozen at certificate issuance.
- Wildcard semantics (`rbac.go:148`) mean an accidental wildcard capability grants transitive access — privilege-escalation surface.

---

## 4. Policy Management & AIC / Delegation

### Mechanism
Signed authorization policies with snapshot/rollback (in-memory), plus AIC (Agent Identity Certificate) parsing/validation and delegation-chain verification with anti-cycle/anti-bomb/anti-recursion protections.

### Implementation
- `AuthorizationPolicy` — `policy.go:26`; `VerifyPolicy` — `policy.go:68` (static namespace/role/capability match only).
- Policy store: `PolicySnapshot`/`PolicyBranch`/`PolicyManager` — `policystore.go:16/34/55`; `NewPolicyManager` — `policystore.go:65`; `Commit`/`Rollback`/`Current`/`History` — `policystore.go:82/110/125/135`.
- AIC: type aliases — `aic.go:16-21`; OID re-exports — `aic.go:35-47`; `ParseAIC` — `aic.go:52`; `HasAIC` — `aic.go:75`; `ValidateAIC` — `aic.go:95`.
- Delegation chain: `ValidateDelegationChain` — `delegation_chain.go:30`; `DefaultMaxChainLength` — `delegation_chain.go:25`. Anti-cycle/anti-bomb/anti-recursion are enforced inline.

### Limitations / defects
- `PolicyManager` snapshots are in-memory ring-buffer only; lost on restart (no disk persistence).
- `DefaultMaxChainLength` is hardcoded and cannot be overridden.
- `VerifyPolicy` does not evaluate conditions/constraints inline — only static matching.
- Finding 20 (`credential_bundle.go:38`): `CredentialBundle.VerifyBundle` validates governance + operational chains independently but does **not** verify the two trust anchors resolve to a shared root.

---

## 5. Certificate Lifecycle / Short-Lived Certs

### Mechanism
Background issuance and renewal of short-lived certificates, credential bundles, and a confirmed-renewal state machine (idle → awaiting-confirmation → confirmed).

### Implementation
- `DefaultRenewInterval`/`DefaultRenewWindow` — `shortlived.go:22/25`; `ShortLivedCertClient` — `shortlived.go:56`; `NewShortLivedCertClient` — `shortlived.go:82`; `IssueCert` — `shortlived.go:102`; `RenewalLoop` — `shortlived.go:145`.
- `CredentialBundle` — `credential_bundle.go:28`; `NewCredentialBundle` — `credential_bundle.go:55`; `VerifyBundle` — `credential_bundle.go:80`.
- `ConfirmedRenewalManager` — `confirmed_renewal.go:47`; state machine (`RenewalIdle`/`AwaitingConfirmation`/`Confirmed`) — `confirmed_renewal.go:37-45`; `RequestRenewal`/`Confirm`/`Reject`/`SignRenewalDA` — `confirmed_renewal.go:95/130/155/180`.
- Renewal token: `RenewalTokenExt` — `renewal_token.go:18`; `ParseRenewalToken` — `renewal_token.go:29`; `IsExpired`/`VerifyNonce` — `renewal_token.go:56/68`.

### Limitations / defects
- **FIXED (2026-09-03): renewal jitter.** `RenewalLoop` (formerly `StartRenewalLoop`) now staggers on startup and jitters each issue call (`renewalJitter`, crypto/rand) to avoid the thundering-herd risk of clients issued together renewing simultaneously.
- Pending renewals are in-memory only; a crash during the confirmation window loses them.
- Finding 20 (cross-chain trust anchor, see §4).

---

## 6. Revocation: CRL & OCSP

### Mechanism
- CRL: per-listener cached CRL with periodic refresh and forced reload; `IsRevoked`/`VerifyCert` drive admission.
- OCSP: per-certificate online status with configurable fallback (allow/deny/CRL) and server-side stapling.

### Implementation (CRL)
- `CRLCache` — `crl.go:42`; `NewCRLCache` — `crl.go:60`; `Refresh` — `crl.go:80`; `Start` — `crl.go:105`; `ForceRefresh` — `crl.go:120`; `IsRevoked` — `crl.go:138`; `VerifyCert` — `crl.go:160`. `Translator` interface — `crl.go:24`.
- Replay detection tracks the last `ThisUpdate` timestamp (`crl.go:42-47`).

### Implementation (OCSP)
- `OCSPFallbackMode` consts — `ocsp.go:18-22`; `OCSPCache` — `ocsp.go:28`; `NewOCSPCache` — `ocsp.go:50`; `Check` — `ocsp.go:80`; `Staple` — `ocsp.go:110`; stapling start `StartOCSPStapling` (used from `http/proxy.go:262`).

### Defects / risk notes
- **Finding 14 (CRL replay):** replay detection is timestamp-based only; a re-issued CRL carrying the same `ThisUpdate` is silently ignored (`crl.go:42-47`).
- `OCSPCache.Staple` returns an empty `[]byte` on failure instead of an error — callers cannot distinguish "no stapling needed" from "responder unreachable".
- With `OCSPFallbackAllow`, a failed/unreachable OCSP check still permits the certificate (`ocsp.go:80`).

---

## 7. Revoker (explicit revocation store)

### Mechanism
Explicit certificate/principal revocation independent of CRL, used for conditional and risk-driven revocation.

### Implementation
- `Revoker` — `revoker.go:45`; `NewRevoker` — `revoker.go:75`; `RevokeCert` — `revoker.go:100`; `RevokeBySerial` — `revoker.go:135`; `RevokeByKeyHash` — `revoker.go:155`.

### Defects / risk notes
- `RevokeBySerial`/`RevokeByKeyHash` do **not** verify that the revoking principal is authorized to revoke the target; authorization is delegated to the caller. Callers (e.g. management API, `RoleAdmin`) must gate it.

---

## 8. Time Stamping Authority (TSA)

### Mechanism
RFC 3161 client for timestamp requests/responses, and a tamper-evident TSA proof logger for audit entries.

### Implementation
- Request/response structs — `tsa.go:18-93`; `TSAClient` — `tsa.go:95`; `NewTSAClient` — `tsa.go:110`; `GetTimestamp` — `tsa.go:130`; `VerifyTimestamp` — `tsa.go:165`.
- `TSAProofEntry`/`TSAProofLogger` — `tsa_proof.go:20/35`; `NewTSAProofLogger` — `tsa_proof.go:50`; `Start` — `tsa_proof.go:70`.

### Limitations / defects
- `GetTimestamp` does not implement RFC 3161 `Accuracy` negotiation or retry-with-backoff on `rejection` status.
- `TSAProofLogger.Start` uses a fixed interval; no configurable flush interval or graceful-shutdown hook.

---

## 9. Audit Logging, Merkle Chain & Index

### Mechanism
Append-only audit log; each entry is hashed into a Merkle chain (leaf/node hashes), producing a `LatestRoot` for tamper evidence. A bbolt-backed `AuditIndex` provides searchable metadata and full-text search.

### Implementation
- `AuditAction*` constants — `audit.go:25-48`; `AuditEntry` — `audit.go:55`; `AuditLogger` — `audit.go:80`; `NewAuditLogger` — `audit.go:100`; `Append` — `audit.go:125`; `Flush` — `audit.go:145`.
- Merkle: `HashLeaf`/`HashNode` — `merkle.go:19/27`; `MerkleTree` — `merkle.go:40`; `NewMerkleTree` — `merkle.go:55`; `Append` — `merkle.go:72`; `LatestRoot` — `merkle.go:95`; `AuditChain` — `merkle.go:108`; `NewAuditChain` — `merkle.go:120`; `Append` — `merkle.go:135`; `Seal` — `merkle.go:155`.
- Index: `AuditIndex` — `audit_index.go:16`; `NewAuditIndex` — `audit_index.go:47`; `Index` — `audit_index.go:73`; `Search` — `audit_index.go:130`; `Size`/`Drop`/`DBPath` — `audit_index.go:243/253/271`. FTS: `IndexFTS`/`SearchFTS` — `audit_fts.go:141/170`. `MaxPostingsPerKey` — `audit_index.go:23`.

### Limitations / defects
- **Finding 22 (domain separation):** `HashLeaf`/`HashNode` (`merkle.go:16-17`) use the same hash with no domain prefix (e.g. `"leaf:"`/`"node:"`); a crafted input could collide a leaf with an internal node, relying on hash collision resistance.
- **Finding 23 (postings bound):** `MaxPostingsPerKey` = 1000 (`audit_index.go:22`). If too low for a busy CN/serial, index queries can silently miss entries; if too high, memory pressure.
- `Search` and `SearchFTS` are separate; there is no single unified search API.
- `Drop` (`audit_index.go:253`) destroys and recreates all buckets atomically but with no backup/export step.

---

## 10. Mesh Networking & Stream Multiplexing

### Mechanism
Peer-to-peer mTLS mesh for inter-gateway federation: revocation broadcast, disconnect propagation, peer sync, connection registry, and stream multiplexing over QUIC-style frames.

### Implementation
- `MeshManager` — `mesh.go:52`; `NewMeshManager` — `mesh.go:80`; `Connect`/`Forward` — `mesh.go:100/135`; `ControlHandler` — `mesh.go:155`.
- Control plane: `ControlRevoke`/`ControlDisconnect`/`ControlPeerSync` — `mesh_control.go:25-30`; `SendRevoke`/`SendDisconnect`/`SendPeerSync` — `mesh_control.go:55/75/95`.
- Multiplexing: `StreamMux` — `streammux.go:30`; `MuxDial`/`MuxAccept` — `streammux.go:65/90`; protocol constants — `streammux.go:18-27`.
- Connection registry: `ConnRegistry` — `registry.go:29`; `Register`/`RegisterConn` — `registry.go:48/55`; `DisconnectByAgentId` — `registry.go:95`; `DisconnectByPrincipalUid` — `registry.go:121`; `ListConnections` — `registry.go:185`.

### Limitations / defects
- `MeshManager.Forward` has no flow control/backpressure — a slow peer causes unbounded buffering.
- Mesh `ControlMessage` (`mesh_control.go:34`) has **no authentication/signature**; the trust model is that any authenticated peer can inject control messages. The underlying transport is mTLS, but message integrity beyond the peer identity is not enforced.
- `StreamMux` read buffer is hardcoded (`streammux.go:24-25`); no configurable sizing.
- `ConnRegistry` uses a linear `findEntry` scan → O(n) per disconnect under high concurrency.

---

## 11. TLS / mTLS Configuration Builders

### Mechanism
Central TLS configuration construction (server/mTLS/client, cipher suites, chain loading) used by all three binaries.

### Implementation
- Protocol constants — `mtls.go:14-31`; TLS mode consts — `mtls.go:36-40`; `TLSConfig` — `mtls.go:46`.
- `BuildServerTLSConfig`/`BuildClientTLSConfig` — `mtls.go:80/115`; `LoadCertificateChain`/`LoadTLSConfig` — `tls.go:75/105`; `SecureCipherSuites`/`BuildCipherSuites` — `tls.go:17/42`.
- Nil-safe accessors (e.g. `IdleTimeout` guards `t == nil`), `mtls.go:206-211` — verified: a nil `*TLSConfig` receiver does **not** panic.

### Limitations / defects
- `SecureCipherSuites` is hardcoded; adding a custom suite requires a source change.
- `BuildServerTLSConfig` does not set `SessionTicketsDisabled`/`ClientAuth` defaults; callers must configure these explicitly.
- `LoadTLSConfig` does not validate that the loaded cert/key form a valid pair before returning.

---

## 12. Identity, Security Utilities & Monitoring

### Mechanism
SPIFFE ID parsing/verification, self/belonging verification, nonce anti-replay cache, risk monitoring, per-cert connection expiry, metrics, connection tracking, and masking helpers.

### Implementation
- SPIFFE: `SPIFFEID` — `spiffe.go:14`; `ExtractSPIFFEIDFromCert` — `spiffe.go:37`; `VerifySPIFFESAN` — `spiffe.go:61`; `ParseSPIFFEID` — `spiffe.go:66`; `BelongsToTrustDomain` — `spiffe.go:80`.
- Self/belonging verification: `VerifySelf`/`VerifySelfWithOptions` — `selfverify.go:32/37`; `VerifyBelongTo` — `belongto.go:31`.
- Nonce: `NonceCache` — `nonce_cache.go:13`; `NewNonceCache` — `nonce_cache.go:25`; `CheckAndAdd` — `nonce_cache.go:56`; `Stop` — `nonce_cache.go:78`.
- Risk: `RiskMonitor` — `riskmonitor.go:55`; `NewRiskMonitor` — `riskmonitor.go:75`; `Evaluate`/`Enforce` — `riskmonitor.go:95/130`.
- Connection expiry: `ConnExpiryRegistry` — `connexpiry.go:36`; `UpdateCert` — `connexpiry.go:75`; `ShouldSkipRevoke` — `connexpiry.go:100`; `StartExpiryCheck` — `connexpiry.go:120`.
- Metrics: `MetricCounter`/`MetricGauge`/`MetricHistogram`/`CollectAll` — `metrics.go:16/57/120/180`.
- Tracking/masking: `ConnectionTracker` — `tracker.go:14`; `MaskString`/`MaskCertSerial`/`MaskFilePath` — `mask.go:17/29/49`. `UserPermission` aliases — `user_permission.go:12-21`.

### Limitations / defects
- `NonceCache` is in-memory with a background janitor; nonces are lost on restart (replay window resets to zero — safe, but can break in-flight requests).
- `RiskMonitor.Evaluate` applies rules in Go map-iteration order (nondeterministic); no priority ordering.
- `ConnExpiryRegistry.ShouldSkipRevoke` linear-scans all tracked certs — bottleneck at thousands of concurrent certs.
- `ConnectionTracker.Snapshot` copies the entire map under a `sync.RWMutex` — GC pressure under high churn.
- `ChainRefStore`/cross-gateway DAG refs (`chainrefs.go:23/42`) are in-memory only; lost on restart.
- `Version` defaults to `"0.1.0"` unless `-ldflags` is used (`version.go:8`) — do not rely on it for gating behavior.

---

## Cross-cutting: Type Aliasing

Many public types are **aliases** into `github.com/varwof/types` (`pki` package): `AIC`, `Capability`, `PrincipalAuthorization`, `DelegationPolicy`, `PluginDecision` (`aic.go:16-21`), `UserPermission*` (`user_permission.go:12-21`), and 10 OID variables (`aic.go:35-47`). Upstream changes in `varwof/types` propagate without any source change here — a compatibility surface to track during upgrades.
