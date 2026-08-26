# AIC × IAM Unification: Dual-Form Identity Design

> Status: 🟡 Core partially landed (2026-08-24): Dual-form identity already implemented by AIC-JWT (`draft-wei-aic-jwt-00`) + `types/aicjwt`;
> **FUTURE**: `/api/v1/token` (AIC→JWT exchange), `/.well-known/jwks.json`, `/.well-known/openid-configuration`, policy point API, multi-language thin SDK
> Date: 2026-08-01 (updated 2026-08-24)
> Topic: AIC as the sole IAM identity source, any mainstream language, any form of App (native/server-side/Web) natively connected

## 0. One Sentence

AIC is already an X.509 certificate that any mainstream language's TLS stack can obtain — but "obtaining the certificate" and "natively consuming AIC semantics" are separated by a layer of ASN.1. To achieve "any language, any form of App natively supporting AIC + IAM unification," the key is not writing an SDK for each language, but defining AIC as a **dual-form identity** carried by language-agnostic standard protocols.

## 1. Unification Model: AIC = IAM's Sole Identity Source

```
                 ┌─────────────────────────────────────────────┐
                 │          AIC (Identity Source / IAM Principal)│
                 │  PrincipalUid · AgentId · Capabilities       │
                 │  ExecutionConstraints · Delegation · Revocation
                 └───────────────┬─────────────────────────────┘
                                 │ Two natural forms (same identity)
              ┌──────────────────┴──────────────────┐
              ▼                                     ▼
   Form 1: X.509 certificate (cryptographic native)   Form 2: JWT claims (language neutral)
   · mTLS peer cert direct                             · Standard JWT/JWKS, ready-made libraries in any language
   · Gateway B2 pass-through X-Client-Cert-DER         · Web's only path (browsers cannot access certificates)
   · App direct handshake with certificate              · Short-lived, with scopes/caps/constraints
              └──────────────────┬──────────────────┘
                                 ▼
              Language-agnostic interface conventions (protocol, not SDK)
```

**Key design decision: AIC identity is projected as JWT claims, rather than making each language parse ASN.1.**
This is the most "native" answer — Java/Node/Python/Rust/C#/PHP all have mature JWT + JWKS libraries, zero custom development needed.
SPIFFE/SPIRE follows exactly this pattern (X.509-SVID and JWT-SVID dual forms), and AIC can naturally follow this definition.

## 2. Three Native Channels for Identity to Reach Apps (by scenario, not fragmented)

| Scenario | Channel | What the application receives | How language consumes |
|---|---|---|---|
| Server/Native App | mTLS direct connection | TLS layer peer cert (AIC) | Standard TLS stack retrieves certificate; certificate → query core API or local cache for claims |
| Server via Gateway | B2 certificate pass-through | `X-Client-Cert-DER` + structured headers | Any HTTP stack reads standard headers; not trusted, context only |
| **Web App / Browser** | Short-lived identity token | Standard JWT (AIC-derived claims) | Standard JWT library verification + local authorization |

Web is the only scenario where client certificates cannot be obtained, so there must be a "use AIC to exchange for short-lived JWT" handshake. This handshake itself is the hub of IAM unification:

```
Web App / Any Language App
   │  ① Holds AIC certificate (mTLS or via gateway)
   ▼
Core  POST /api/v1/token    ← Exchange AIC for short-lived JWT (JWKS signed)
   │  ② Returns JWT: { sub=principal_uid, agent_id, scopes=capabilities,
   │                exp=min(certificate validity, ExecutionConstraints), ... }
   ▼
App   GET /jwks → Standard JWT library verification → Extract claims → Local policy execution
```

This way, all languages and all forms of App have only **two standard actions**: verify JWT (using JWKS) + read claims
(standard fields). AIC's Capabilities project to `scopes`, ExecutionConstraints project to
`exp/nbf` + constraint fields, PrincipalUid/AgentId project to `sub` + dedicated claims — identity, permissions,
and policy dimensions are all language-neutral.

## 3. Four Pillars of Unification

1. **Identity Recognition**: `sub` = PrincipalUid, `agent_id` = AgentId, any language recognizes `sub`
   (OIDC semantics)
2. **Permission Control**: `scopes` = AIC Capabilities (corresponding to core permission model, e.g., `ca:issue`,
   `cert:revoke`); applications make local decisions without querying core each time
3. **Execution Policy**: JWT built-in `exp/nbf` (ExecutionConstraints hard timeout projection) + audit chain reference;
   Complex constraints (CIDR, capability intersection) executed by "policy point" — can be embedded (lightweight) or call core `/authorize`
   (strong consistency)
4. **Unified Audit**: All Apps consume the same JWT, logs carry the same `sub`/`agent_id`/JWT id, Merkle
   chain full coverage — from "authentication to execution" the entire chain is unbroken

## 4. Gateway Positioning Becomes Clear

The gateway is no longer an "identity intermediary" but a **form converter**: X.509 (client certificate) → pass-through certificate headers (for server
App) or → JWT exchange (for Web/cross-language). Core remains the sole issuance source; the gateway is just a channel + converter without changing
the trust model. This also explains why B2 (certificate pass-through) and `/session` (identity detection) are the natural first two steps of this model.

## 5. Implementation Path (Language-Agnostic, Protocol First, SDK Later)

- **P0 Protocol Layer**: `/api/v1/token` (certificate→JWT) + `GET /jwks` + standard claim mapping table. Once this
  interface is defined, any language can connect directly, **no need to wait for SDK**
- **P1 Reference Implementation**: Write a "thin" reference SDK for 2-3 mainstream languages (verification + claims extraction + local
  authorization helper) to prove protocol completeness; other languages implement per protocol
- **P2 Policy Point**: Define unified policy format (JSON/Cedar/Rego choose one); application side can evaluate locally or delegate
  remotely

## 6. Decision Records (Finalized 2026-08-01, Not Yet Implemented)

| # | Decision Point | Conclusion |
|---|---------------|------------|
| 1 | Intermediate representation | **JWT/OIDC** (widest ecosystem); unified JWT simultaneously satisfies SPIFFE JWT-SVID + RFC 9068 (see `11-spiffe-oauth.md`) |
| 2 | Policy evaluation deployment form | **Two-level authorization decided**: L1 embedded (gateway local, coarse-grained/offline) + L2 centralized (core online API, fine-grained), coexisting by sensitivity level |
| 3 | P1 reference SDK languages | **Go + Python + Node** three languages |

> Supplementary finalization (revised 2026-08-24, aligned with draft §18): `iss` maintains OAuth/RFC 9068 URL (JWT-SVID does not read iss,
> trust domain anchored by sub + SPIFFE bundle); in SPIFFE mode `sub` directly inherits certificate agentId (i.e., SPIFFE ID);
> token endpoint accepts AIC mTLS + B2 + /session three channel types. See `11-spiffe-oauth.md` §8/§11 for details.

## 7. Connection with Current Repository Status

- Ready: B2 certificate pass-through (`X-Client-Cert-DER` + structured headers), `/api/v1/session` identity detection,
  AIC parsing (`internal/ca` + pki-gateway-lib), JWT capability (OIDC provisioner already has pure
  stdlib JWT verification, reusable for issuance)
- To build: `/api/v1/token` (certificate→JWT), `/jwks`, claim mapping table, policy point API
