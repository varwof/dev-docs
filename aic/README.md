# Varwof PKI Project — AIC Identity & Authorization Specification

> [中文版](README_CN.md)

> Version: v1.7.1
> Date: 2026-08-26 (continuously updated; authoritative OID tree in `07-oid-tree.md`)
> Finalized (multi-level delegation chain is FUTURE)

> **IPR Notice**: This document is subject to BCP 79 (RFC 8179). The author has filed patent applications related to the technologies described herein:
>
> - **CN2026112384541** — 一种基于 X.509 数字证书扩展的 AI Agent 身份与委托授权绑定的证书结构 (*A Certificate Structure for Binding AI Agent Identity and Delegated Authorization Based on X.509 Digital Certificate Extension*)
> - **CN2026112384607** — 一种基于数字证书扩展的离线自包含网关授权与生命周期管理设备 (*An Offline Self-Contained Gateway Authorization and Lifecycle Management Device Based on Digital Certificate Extension*)
>
> IPR disclosures are available through the [IETF IPR disclosure system](https://datatracker.ietf.org/ipr/):
>
> - [IPR 7553](https://datatracker.ietf.org/ipr/7553) — Jijie Wei's Statement about IPR related to draft-wei-aic-identity-cert (2026-08-19)
> - [IPR 7565](https://datatracker.ietf.org/ipr/7565) — Jijie Wei's Statement about IPR related to draft-wei-aic-jwt (2026-08-24)
>
> IPR disclosures [7553](https://datatracker.ietf.org/ipr/7553) and [7565](https://datatracker.ietf.org/ipr/7565) have been filed in accordance with BCP 79. Patents are held for defensive purposes; all implementers are licensed royalty-free under these disclosures. All licenses are Royalty-Free, Reasonable and Non-Discriminatory to all implementers.

## Overview

AIC (Agent Identity Certificate) is an AI Agent identity and authorization framework based on X.509 v3 certificate extensions. It anchors IAM authorization results (Principal Authorization + Capability) into tamper-proof, offline-verifiable certificate structures for Gateway runtime execution.

### Three Planes

```
┌─────────────────────────────────────┐
│  IAM (Management Plane)             │  Management Plane: defines identity, roles, authorization
└──────────────┬──────────────────────┘
               │ Authorization result: PrincipalAuthorization + Capability
               ▼
┌─────────────────────────────────────┐
│  AIC / PKI (Trust Distribution)     │  Distribution Plane: certificate issuance, identity binding, evidence consolidation
└──────────────┬──────────────────────┘
               │ Issue Agent certificate
               ▼
┌─────────────────────────────────────┐
│  Gateway (Enforcement Plane)        │  Enforcement Plane: identity verification, permission intersection, policy enforcement
└─────────────────────────────────────┘
```

### Design Principles

- **Core is stable; semantics are extensible** — The core stays small and stable; business semantics extend through Capability Schemes
- **Capability is the only container** — The Core only defines the Capability structure, not specific capability semantics
- **User certificate as trust root** — Principal signature is the cryptographic anchor of authorization
- **Offline self-contained** — Verifiers can complete identity authentication and authorization decisions without network access
- **Single-level delegation (default), extensible to multi-level delegation chain (FUTURE)** — Principal → Agent, with future support for Agent → sub-Agent
- **Constrained but not overstepping** — Only constraints belonging to the authorization boundary are placed in the certificate (determined by the authorizer, varies per individual, infrequent changes); operational policies, business preferences, and temporary configurations are not placed in the certificate
- **Enterprise privilege autonomy** — The `PrincipalAuthorization` extension can function independently of Agent delegation as infrastructure for enterprise employee privilege management |

### Directory Structure

#### Core Specification (stable, can be directly referenced)

| File | Content |
|------|---------|
| `01-asn1.md` | ASN.1 type definitions (AIC/DA/PA/Reason/PrincipalUid) |
| `02-code-map.md` | Go struct ↔ ASN.1 mapping + code location |
| `03-validation.md` | ValidateAIC validation rules (V6/V8/R1-R10) |
| `04-examples.md` | Encoding/decoding examples (DER/PEM/JSON) |
| `05-capability.md` | Capability specification (string format, Parameters, Glob matching, built-in schemes) |
| `06-delegation-auth.md` | DelegationAuthorization signing and verification flow |
| `07-oid-tree.md` | OID tree (1.3.6.1.4.1.66257) |

#### Deployment Modes (FUTURE / Partial Implementation)

| File | Content | Status |
|------|---------|--------|
| `08-dual-cert.md` | Dual-certificate deployment (handshake cert + authorization cert, bypassing QUIC 16KB limit) | FUTURE |
| `09-aic-iam-unification.md` | AIC × IAM unified identity (dual-form: X.509 + JWT) | ✅ L0–L4 implemented (2026-08-31) |
| `10-enterprise-authz.md` | Enterprise privilege autonomy (PrincipalAuthorization + authz.json) | 🟡 Partial |
| `11-spiffe-oauth.md` | AIC × SPIFFE × OAuth/OIDC interoperability specification | ⚠️ Deferred |
| `12-identity-source.md` | LDAP/AD identity source integration (bridge-ldap/bridge-oauth) | ⚠️ Deferred |

#### Reference

| File | Content |
|------|---------|
| `13-revision-history.md` | Change log (v1.0 → v1.8) |
| `14-version-governance.md` | Version governance policy (freeze/release process) |

## OID Tree

### Root OID

```
1.3.6.1.4.1.66257 (IANA PEN — Varwof PKI Project)
```

IANA PEN 66257, officially approved in July 2026.

### Official OID Tree

```
1.3.6.1.4.1.66257
│
├── 1  Core Identity & Authorization
│   ├── 1  AIC                     ── Agent identity certificate extension
│   │   ├── 1  AgentIdentity       ── agentId, principalUid, delegationMode
│   │   ├── 2  DelegationAuthorization ── Principal signature evidence
│   │   ├── 4  DelegationDepthControl  ── (FUTURE) Delegation depth control
│   │   │   ├── 1  chainDepth      ── Current delegation level
│   │   │   └── 2  maxDepth        ── Maximum allowed delegation depth
│   │
│   ├── 2  PrincipalAuthorization  ── Principal authorization declaration; delegationPolicy is an ASN.1 field inside the extension, NOT a sub-OID
│   │
│   ├── 3  OfflineRBAC            ── Removed (2026-08): value .1.3, no production caller
│   ├── 4  PrincipalProfile       ── Removed (2026-08): value .1.4, no production caller
│   ├── 5  GatewaySession (historical) ── Pre-v1.5 gateway session extension (migrated to AIC.authorizationConstraints); branch kept for gateway-related sub-OIDs
│   │   └── 1  Sub-CA scope       ── Active: sub-CA scope .1.5.1, in production use
│   └── 6  RenewalToken            ── (Reserved) Authorization renewal token
│
├── 2  ASN.1 Module Identifiers
│   └── 1  id-mod-varwof-aic       ── ASN.1 module arc { 1 3 6 1 4 1 66257 2 1 } (I-D §1.3)
│
├── 3  National/Industry Certifications
│   ├── 1  MarketAccessId          ── Market access container
│   ├── 2  TrustLevel              ── Trust level
│   └── 3  CrossBorder             ── (Reserved) Cross-border mutual recognition
│
├── 5  Chinese Cryptography Algorithm Identifiers
│   ├── 1  SM2-Signature
│   ├── 2  SM3-Hash
│   ├── 3  SM4-Encryption
│   └── 4  SM2-SM3-Signature
│
└── 6  Certificate Transparency Integration
    ├── 1  SCT                     ── SignedCertificateTimestamp
    └── 2  CTLog                   ── CT log identifier
```

### OID Mapping Table

| OID | Name | Type |
|:---:|------|:----:|
| `1.3.6.1.4.1.66257.1.1` | AIC | X.509 Extension |
| `.1.1.1` | AgentIdentity | AIC child node |
| `.1.1.2` | DelegationAuthorization | AIC child node |
| `.1.1.4` | DelegationDepthControl | AIC child node (FUTURE) |
| `.1.1.4.1` | chainDepth | DDC child node (FUTURE) |
| `.1.1.4.2` | maxDepth | DDC child node (FUTURE) |
| `.1.2` | PrincipalAuthorization | X.509 Extension |
| `.1.3` | OfflineRBAC | Removed: no production caller |
| `.1.4` | PrincipalProfile | Removed: no production caller |
| `.1.5` | GatewaySession | Historical gateway session extension (sub-CA scope .1.5.1 in production use) |
| `.1.5.1` | Sub-CA scope | CA scope extension (active) |
| `.1.6` | RenewalToken | Authorization renewal token |
| `.2.1` | id-mod-varwof-aic | ASN.1 module identifier (I-D §1.3) |
| `.3.1` | MarketAccessId | National certification extension |
| `.3.2` | TrustLevel | Trust level |
| `.5.1` | SM2-Signature | Chinese cryptography algorithm |
| `.5.2` | SM3-Hash | Chinese cryptography algorithm |
| `.5.3` | SM4-Encryption | Chinese cryptography algorithm |
| `.5.4` | SM2-SM3-Signature | Chinese cryptography algorithm |
| `.6.1` | SCT | CT extension |
| `.6.2` | CTLog | CT extension |

> Design principle: The Core only maintains identity, authorization, and capability containers. Algorithm suites, execution policy parameters, Certificate Transparency, etc. extend through external standards or Capability Schemes and are not redundantly defined in the Core OID tree. The `authorizationConstraints` added in v1.6 reuses the Capability container without adding new OIDs.

## Authorization Verification Flow

After completing certificate chain verification, the receiver proceeds as follows:

1. **Extract** the AIC
2. **Locate the principal public key** — Match via principalUid.keyHash in the credential bundle
3. **Verify the principal certificate chain** to the trust root
4. **Verify signature** — Verify delegationAuthorization.signatureValue using the principal public key
5. **CA verifies DelegationAuthTBS** — Timestamp freshness + nonce uniqueness (issuance protocol stage)
6. **Determine delegation mode** — authorized uses capabilities only; representative requires verifying capabilities ⊆ PrincipalAuthorization.grants
7. **Check chainDepth ≤ maxDepth (FUTURE)** — Multi-level delegation chain depth control
8. **Check authorizationConstraints** — **Check constraints first (low-cost fast rejection)**; all constraints MUST be simultaneously satisfied (AND logic)
9. **Check capabilities** — Then check business capabilities
10. **Execute Capability Scheme routing** — Dispatch to plugins by schemeId
11. **Apply Gateway Policy** — Runtime policies (timeout/retry/rate-limiting/routing)
12. **Audit log** — Record agentId, principalUid, decision, timestamp

> Steps 7–8 are in fixed order: constraint checks (time/IP/concurrency) have lower cost than business capability checks and should be executed first during the TLS handshake phase to quickly reject non-compliant requests.

## Deployment Profiles

### Standard Deployment (Single Certificate)

The Agent holds a complete AIC certificate (containing capabilities + authorizationConstraints) and presents it all at once during the TLS handshake. Suitable for protocols like TCP/HTTP mTLS where the Certificate message has no size limit.

### Dual-Certificate Deployment (Handshake Certificate + Authorization Certificate)

> See [`08-dual-cert.md`](08-dual-cert.md) for details.

In QUIC/DTLS environments, due to the approximately 16KB hard limit on the Certificate message during the TLS handshake phase (RFC 9000), deployment MAY split the AIC certificate into:

- **Handshake certificate**: Contains only `agentId`, `principalUid`, `delegationMode`, `DelegationAuthorization`, used for mTLS handshake; `capabilities` must have at least one entry (AIC validation requires non-empty; specific placeholder capabilities are defined by deployment per registry). SHOULD NOT exceed 8KB.
- **Authorization certificate**: Contains `capabilities`, `authorizationConstraints`, and extension information, transmitted via application layer after handshake completion. SHOULD NOT exceed 64KB.

Both certificates are issued by the same CA with a consistent trust chain. This is a deployment strategy optimization that does not change the AIC protocol definition.
