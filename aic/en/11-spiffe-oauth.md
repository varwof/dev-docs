# AIC × SPIFFE × OAuth/OIDC Interoperability Specification

> ⚠️ **Deferred**: This document covers OAuth/OIDC integration; to be updated after related components are released.

> Status: 🟢 Core SPIFFE/AIC-JWT landed (2026-08-24 implementation aligned)
> **FUTURE**: §4 OIDC endpoints (`/api/v1/token`, `/.well-known/jwks.json`, `/.well-known/openid-configuration`); L2 online policy endpoint (`/api/v1/authorize`)
> Date: 2026-08-01 (updated 2026-08-24)
> Positioning: Direct compatibility, not bridging. AIC identity is simultaneously a SPIFFE SVID and OAuth/OIDC principal — one identity, three standard views.
> Related: `09-aic-iam-unification.md` (dual-form identity overall design)
> Implementation alignment: AIC-JWT (`draft-wei-aic-jwt-00`) has landed as an application-layer Profile,
> claim compatibility mapping see draft §18 (AIC-JWT ↔ Unified JWT Profile).

## 0. One Sentence

The AIC certificate itself is an X.509 certificate, and the AIC-derived JWT naturally satisfies both **SPIFFE JWT-SVID** and **RFC 9068 (OAuth 2.0 JWT access token)** specifications. Therefore, no "bridging layer" is needed:
only need to agree on (a) AIC certificate carries SPIFFE URI SAN, (b) unified JWT claim mapping — and the SPIFFE and OAuth ecosystems can natively consume AIC identity.

## 1. Unified Identity Model: One AIC, Three Standard Views

```
                   ┌───────────────────────────┐
                   │     AIC (Sole Identity Source)│
                   │  PrincipalUid · AgentId    │
                   │  Capabilities · Constraints│
                   └───────────┬───────────────┘
                               │
      ┌────────────────────────┼─────────────────────────┐
      ▼                        ▼                         ▼
  X.509 View               JWT View (Unified Profile)    OIDC/OAuth View
  = SPIFFE X.509-SVID      = SPIFFE JWT-SVID            = RFC 9068 access token
  (spiffe:// URI SAN)      (sub=spiffe:// ID)           (iss/aud/scope/exp/jti)
                           + AIC claims                 + AIC claims
```

**Design key**: All three share the same cryptographic identity (same public key / same CA / same JWKS key), merely projected into different standard formats. SPIFFE verifiers look at `sub=spiffe://...`, OAuth resource servers look at `scope`/`iss`, AIC applications look at `principal_uid`/`capabilities` — **same JWT, no conflicts**.

## 2. Specification A: AIC Certificate = SPIFFE X.509-SVID

### 2.1 URI SAN Convention

AIC certificates MUST carry SPIFFE ID URI SAN when issued. SPIFFE ID is derived from the certificate identity:

```
Agent identity:    spiffe://<trust-domain>/agent/<agentId>
Principal identity: spiffe://<trust-domain>/principal/<principalUid>
```

- `<trust-domain>`: Enterprise trust domain (e.g., `varwof.com`), consistent with core trust domain configuration
- Existing `urn:pki:ca:<scope>` URI SANs can coexist (SPIFFE allows additional URI SANs)
- Certificate AIC extension (`.1.1`) unchanged; SPIFFE ID is just a standard projection, **no new OID needed**

### 2.2 SPIRE Integration

- Core CA serves as trust root for SPIFFE trust bundle: register core CA certificate in SPIRE trust bundle (bundle for `spiffe://<td>`)
- SPIRE workload uses standard SPIRE agent to verify AIC certificate = verifying X.509-SVID
- No need to implement SPIRE Workload API: when enterprise already has SPIRE, consume directly; without SPIRE, AIC certificate can be parsed by any SPIFFE-compatible verifier per SPIFFE spec

### 2.3 Reverse: SPIFFE X.509-SVID → AIC Semantics

Certificates carrying `spiffe://<td>/principal/<uid>` or `/agent/<id>` URI SAN can be parsed and mapped by core to AIC principal/agent (URI SAN → PrincipalUid). If the certificate also contains the AIC extension, it is directly an AIC.

## 3. Specification B: Unified JWT Profile (Simultaneously JWT-SVID + OAuth Access Token)

### 3.1 Claim Mapping Table (AIC ↔ Standards)

| AIC Concept | Unified JWT Claim | SPIFFE JWT-SVID View | OAuth/RFC 9068 View |
|---|---|---|---|
| PrincipalUid | `principal_uid` | — (path segment) | — |
| AgentId | `agent_id` | Path segment `/agent/<id>` | — |
| SPIFFE ID | `sub` | `sub` MUST = spiffe:// ID | `sub` (RFC 9068 does not restrict format) |
| Trust Domain | `iss` (maintains OAuth URL) | Trust domain (anchored by `sub` + SPIFFE bundle; JWT-SVID does not read iss) | `iss` (RFC 9068) |
| Capabilities | `scope` + `capabilities` | — (aud optional) | `scope` (space-separated) |
| Execution constraint hard timeout | `exp` / `nbf` | `exp` | `exp` |
| Session initiation | `iat` | `iat` | `iat` |
| Audit / anti-replay | `jti` | — | `jti` |
| Delegation mode | `delegation_mode` | — | — |
| Resource scope | `aud` | `aud` (MUST ≥1) | `aud` |

### 3.2 Unified JWT Example

```json
{
  "iss": "spiffe://varwof.com",
  "sub": "spiffe://varwof.com/agent/agent-1",
  "aud": ["api://internal-service"],
  "exp": 1770000000,
  "iat": 1769996400,
  "nbf": 1769996400,
  "jti": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "scope": "ca:issue cert:revoke",
  "aic": {
    "capabilities": ["ca:issue", "cert:revoke"],
    "principal_uid": "varwof:alice:",
    "agent_id": "agent-1",
    "delegation_mode": "representative"
  }
}
```

> `capabilities`/`principal_uid`/`agent_id`/`delegation_mode` are nested within the `aic` claim (`types/aicjwt/claims.go` `AICClaims`);
> `scope` is at the top level (space-separated string, RFC 9068 compatible).

- **SPIFFE verifier**: Verify `sub` (spiffe://) + `aud` + signature (JWKS) → JWT-SVID ✅
- **OAuth resource server**: Verify `iss`/`aud`/`scope`/`exp`/`jti` + signature (JWKS) → RFC 9068 ✅
- **AIC application**: Read `principal_uid`/`capabilities`/`delegation_mode` → local authorization decision ✅

> Same signing key, same JWKS, three consumers each take what they need, no bridging conversion.

## 4. Specification C: OIDC/OAuth Endpoints (Core as IdP) — **FUTURE (Not Implemented)**

The following endpoints are design goals, not yet implemented in core. Current core has no `/.well-known/*` endpoint;
`/api/v1/token` (core) is used for OAuth password grant upstream consumption (not AIC→JWT exchange).

| Endpoint | Function | Compatible Standard | Status |
|---|---|---|---|
| `POST /api/v1/token` | AIC certificate (mTLS) → short-lived JWT | client_credentials + mTLS client_auth | FUTURE |
| `GET /.well-known/jwks.json` | JWT verification public key set | OIDC / JWT-SVID shared | FUTURE |
| `GET /.well-known/openid-configuration` | OIDC discovery | OIDC | FUTURE |
| `GET /.well-known/spiffe/...` (optional) | SPIFFE bundle publication | SPIFFE trust bundle | FUTURE |

### 4.1 Issuance Flow

```
App (any language)
   │  mTLS (AIC certificate) or via gateway B2 pass-through
   ▼
POST /api/v1/token   grant_type=client_credentials
   ▼
Core: Verify AIC → Derive SPIFFE ID → Compute capabilities ∩ policy
      → Issue unified JWT (exp = min(certificate validity, ExecutionConstraints))
   ▼
App holds unified JWT → Verify with /jwks → Local consumption (SPIFFE / OAuth / AIC any perspective)
```

### 4.2 OIDC Compatibility

- `iss` can simultaneously be published as OIDC issuer (`https://pki.varwof.com`) and SPIFFE trust domain
  (`spiffe://varwof.com`) dual views (see §8 decision records)
- Third-party OAuth/OIDC resource servers directly use core JWKS to verify tokens for authorization
- Reverse: Third-party IdP login uses existing OIDC provisioner (third-party JWT → map user roles)

## 5. Conversion Matrix (Technical Interconversion Methods)

| Source | Target | Method | New Code Needed |
|---|---|---|---|
| AIC certificate | SPIFFE X.509-SVID | Include `spiffe://` URI SAN at issuance | Issuance side + trust domain configuration |
| AIC certificate | SPIFFE JWT-SVID | `POST /api/v1/token` (mTLS) → unified JWT | FUTURE (new endpoint + JWKS) |
| AIC certificate | OAuth access token | Same (same JWT, RFC 9068 view) | Reuse |
| SPIFFE X.509-SVID | AIC semantics | URI SAN `spiffe://.../principal/<uid>` → PrincipalUid | Parser |
| SPIFFE JWT-SVID | AIC delegation | Unified JWT already carries AIC claims | Reuse |
| OAuth third-party token | AIC user identity | OIDC provisioner (already exists): third-party JWT → user roles | Implemented |
| OAuth token | AIC permissions | `scope`/`capabilities` intersection mapping | Mapping function |
| Web App (no certificate) | Unified JWT | `POST /api/v1/token` (via gateway B2 or `/session` exchange) | Reuse |
| LDAP/AD user | AIC certificate | Query directory at issuance to fill subject + memberOf → roles | Partially implemented |
| LDAP/AD user | Unified JWT | LDAP provisioner: bind authentication + groups→roles → unified JWT (see `13`) | New provisioner |
| LDAP/AD status | Certificate revocation | Directory disabled/deleted → `RevokeByPrincipalUid` auto-revocation (see `13`) | Sync task |

> Core insight: **JWT-SVID / OAuth access token / AIC-JWT are three perspectives of the same JWT**, so most conversions are "same credential, different parsing method" rather than format conversion.

## 6. Coverage Boundary Analysis (What It Solves, What It Doesn't)

### 6.1 Coverage Assessment

Conclusion: **Identity ~95%, Permissions ~80%, Execution Policy ~75%** — the three solve the **identity pipeline problem**
(who you are, what you can do, how to execute across languages), which is the hardest 90% in distributed systems; the rest is
**business semantics**, which should never be the identity framework's responsibility.

### 6.2 Three-Plane Complements (Non-Overlapping Competition)

The three are complementary sets from three different planes, not competitive:

| Plane | Responsibility | Problem Solved By |
|---|---|---|
| OAuth/OIDC | **Human** identity + delegated authorization (bearer token, resource server) | Google/GitHub login, Web, third-party IdP |
| SPIFFE/SPIRE | **Workload** identity (service-to-service in dynamic orchestration) | K8s, microservices, containers |
| AIC | **Agent** identity + embedded authorization results (X.509 extensions, offline self-contained) | AI Agents, own PKI |

AIC is simultaneously both's standard form: **certificate with SPIFFE URI SAN = X.509-SVID, AIC→JWT =
JWT-SVID ∩ RFC 9068**. Coverage completeness comes from "one identity can enter all ecosystems," not three separate identities each managing their own domain.

### 6.3 Honest Gap List (Clearly Marking Responsibility Boundaries)

| Gap | Why the Three Don't Cover It | Workaround |
|---|---|---|
| Fine-grained relational authorization (folder/document ACL) | OAuth scope too coarse, SPIFFE doesn't handle business authorization | FUTURE: fine-grained authorization API |
| Attribute-level authorization (IP/time/device context) | Identity frameworks only handle identity | **Built-in**: `/authorize` context parameters (see `12`) |
| Business policy semantics | Framework provides pipeline, not "rule content" | **Built-in pipeline**: webhook plugin + `/policies` policy API; semantics defined by business side (see `12`) |
| Hardware/device trust (TPM, DICE, confidential computing attestation) | Identity ≠ hardware evidence | TPM attestation, attestation service |
| Data encryption and KMS | Identity decides "who," not "which key for data" | Vault/HSM, envelope encryption |
| Legally binding signatures (eIDAS, Chinese cryptography compliance) | Requires compliant signing certificates | Independent signing certificate system (Chinese cryptography OID tree can support) |
| Directory lifecycle (onboarding/offboarding/group sync) | Authentication ≠ directory sync | **Built-in**: LDAP/AD sync + status→revocation + groups→roles (see `12-identity-source.md`); SCIM optional |
| Domain policy **semantics** (risk limits, ML security policies) | Framework provides pipeline, not "rule content" | Business-side policy engine |

The 75% gap in execution policy is essentially: **the pipeline (enforcement point) all three can fully cover — gateway,
in-app JWT local decision, centralized authorize — but policy "content" must always be defined by the business side**. The framework provides the pipeline, the domain provides the semantics, neither overstepping.

## 7. Cross-Language Interoperability Analysis (Seven Mainstream Languages)

### 7.1 Interoperability Conclusion

**This works, and it's the smoothest part of this design.** The interoperability surface converges on two IETF standards — JWT/JWKS +
X.509/mTLS — each language has a decade of mature libraries:

| Language | JWT + JWKS Verification | AIC Claims Consumption |
|---|---|---|
| JavaScript/TypeScript | `jose` (node + browser `jose-webcrypto`) | ✅ Read standard JSON |
| Go | `golang-jwt/jwt` / `lestrrat-go/jwx` | ✅ |
| Python | `PyJWT` / `authlib` | ✅ |
| C/C++ | `jwt-cpp` / `libjwt` / OpenSSL 3.x | ✅ (most effort but feasible) |
| C#/.NET | `System.IdentityModel.Tokens.Jwt` | ✅ |
| Java | `Nimbus JOSE + JWT` (de facto standard) | ✅ |
| Rust | `jsonwebtoken` crate | ✅ |

### 7.2 Mechanism

AIC's ASN.1 semantics are parsed only once on the **issuance side** and projected into claims (`principal_uid`/
`capabilities`/`delegation_mode` are all plain JSON); the **consumer side only ever touches standard JSON +
standard digital timestamps**. Java doesn't need to understand ASN.1, Rust doesn't need to understand AIC extensions — language interoperability is determined by protocol design,
not by SDK (reference SDKs are just thin wrappers).

### 7.3 Pitfalls That Specifications Must Pin Down

| # | Pitfall | Specification Requirement |
|---|---------|--------------------------|
| 1 | Algorithm confusion attack | Only sign `RS256/ES256/PS256`; forbid `RS1/RSA1.5`, forbid `alg=none` |
| 2 | JWK format differences | RSA uses `n/e`; EC uses P-256/P-384 with consistent `crv` (Java/C# differ on EC `x/y` encoding) |
| 3 | Key rotation | Must emit `kid`; consumers cache and switch by `kid`; test coverage for rotation |
| 4 | Fixed types | NumericDate in seconds; `aud`/`scope` type (string vs array) fixed |
| 5 | Browser cannot access mTLS | Web channel uses `/session` to exchange unified JWT (native use case for unified JWT) |
| 6 | C/C++ has no runtime ecosystem | Provide Go-written `verify-jwt` CLI fallback + reference implementation |

## 8. Decision Records (Finalized 2026-08-01)

| # | Decision Point | Conclusion | Impact |
|---|---------------|------------|--------|
| 1 | iss/sub issuer view | **Revised (2026-08-24, aligned with draft §18)**: `iss` maintains OAuth/RFC 9068 URL; JWT-SVID verifier does not process `iss`, trust domain anchored by `sub` (SPIFFE ID) + SPIFFE bundle used for verification; `sub` in is_spiffe mode directly inherits certificate agentId (i.e., SPIFFE ID) | RFC 9068 compliant + JWT-SVID compatible (only `typ` needs projection) |
| 2 | sub value | **sub = SPIFFE ID** (`spiffe://<td>/agent/<id>`); `principal_uid`/`agent_id` placed in custom claims | JWT-SVID strong requirement satisfied, OIDC does not restrict sub format, dual-compatible |
| 3 | JWT validity period | Aligned with `ExecutionConstraints` hard timeout: `exp = min(remaining certificate validity, constraint hard timeout, session TTL)` | Short-lived, anti-replay |
| 4 | Token endpoint authorization scope | **AIC mTLS + gateway B2 pass-through + /session representation token** three channel types can all issue | Covers all access forms |
| 5 | P1 reference implementation languages | **Go + Python + Node** three languages | Covers server-side / AI Agent / Web three ecosystems |
| 6 | Permission/policy enforcement built-in | **Core as PDP, gateway as PEP**, two-level authorization (L1 local / L2 online) | FUTURE: fine-grained policy API |
| 7 | Identity source | **LDAP/AD as first-class identity source** (groups→roles / status→revocation / directory authentication→JWT / directory synchronization), not SCIM add-on | Covers enterprise existing directories (see `12-identity-source.md`) |

> Related open items (non-blocking, decided in P2 phase): Policy evaluation embedded vs centralized (`09` decision point 2) already implemented by two-level authorization scheme — **L1 embedded + L2 centralized coexisting, by sensitivity level**.

## 9. Relationship to Existing Specifications

- **OID tree unchanged**: SPIFFE ID uses URI SAN (standard field), JWT profile uses external format, neither requires
  new OID, consistent with "Core is stable; semantics are extensible"
- **Reuse**: B2 certificate pass-through (`X-Client-Cert-DER`), `/api/v1/session`, OIDC provisioner's
  pure stdlib JWT verification (extensible to issuance)
- **v1.7 finalization unaffected**: This specification is an interoperability profile, does not modify AIC core definitions

## 10. Relationship to 09

`09-aic-iam-unification.md` defines the "dual-form identity + any language access" overall framework; this specification is its
**SPIFFE/OAuth standardization profile** — explicitly defining JWT form to simultaneously satisfy JWT-SVID + RFC 9068, explicitly defining
X.509 form as X.509-SVID, making interoperability land on public standards rather than private conventions.

---

## 11. Implementation Landing Alignment (2026-08-24)

The following capabilities have moved from design document to implementation:

### 11.1 SPIFFE (X.509 Side)

- **is_spiffe mode**: `types/aic.go`'s `BuildSPIFFEID/ValidateSPIFFEID/AddSPIFFESANToCert`;
  issuance API (`core/internal/serve/api_ops.go`) `is_spiffe + spiffe_trust_domain` parameters,
  at issuance time agentId dual-written as `spiffe://<td>/agent/<id>` and written to certificate SAN URI
  (`core/internal/ca/sign.go`).
- **Path naming**: Unified as singular `/agent/` (`spiffe://<td>/agent/<agentId>`), consistent with draft §18.
- **Gateway admission**: `gateway-core/spiffe.go` (parsing/validation) + `PipelineConfig` new fields
  `RequireSPIFFE / AllowedSPIFFEIDs / SPIFFETrustDomain`; TLS config
  `require_spiffe / allowed_spiffe_ids / spiffe_trust_domain`; six integration points across http/tcp/udp.
- **Audit**: `AuditEntry.SPIFFEID` (`spiffe_id`) written with connection/rejection/plugin decisions, included in full-text search.

### 11.2 AIC-JWT (OAuth Side)

- **Core implementation source**: `types/aicjwt` sub-package (claims/JWS/§6.2 capability matching/constraints/key binding/11-step verification),
  reusing `types`'s SPKI hash and Capability (`CapToPKI/PKIToCap` bridge).
- **Independent reference repository**: `aic-jwt` changed to `replace` reference
  to `types/aicjwt` wrapper layer, retaining OAuth protocol simulation (RFC 7523/8693/9449, state list, OBO) and scenario tests.
- **Draft §18 rules** (revision 5): `iss` maintains OAuth URL (JWT-SVID does not read iss, trust domain anchored by
  sub+bundle); signing key SHOULD dual-publish (OAuth JWKS + SPIFFE bundle `use=jwt-svid`);
  `typ` retains `aic+jwt`; cross-ecosystem presentation requires projection token (`typ=JWT` + single aud); in SPIFFE mode
  `sub` directly inherits SPIFFE ID, zero conversion.

### 11.3 OAuth/OIDC Identity Source

- `bridge-oauth`: OAuth/OIDC identity source bridge (Keycloak/Auth0/Okta/Entra/GitHub),
  multi-backend token cache + singleflight + userinfo mapping; core's
  `identity-user` profile consumes its password grant + userinfo endpoint via `IdentitySourceOAuth` (`core/internal/ca/identity.go`),
  completing the "identity source → basic identity certificate" closed loop.
- Positioning: Human identity source (LDAP/AD corresponds to `bridge-ldap`), connecting with AIC principal binding,
  non-overlapping with AIC-JWT's AS-side issuance.

### 11.4 Convergence of Differences with Draft

AIC-JWT and JWT-SVID token-layer differences have converged to the only hard conflict (`typ`), the rest are value-add semantics;
deployment-level gateways can treat SPIFFE ID as an independent admission dimension orthogonal to AIC authorization.
