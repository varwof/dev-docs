# DelegationAuthorization Signing and Verification Flow

> Code: `core/internal/ca/aic.go` (issuance), `gateway-core/decision.go` (verification)

## Overview

DelegationAuthorization is the cryptographic evidence of a principal (user) delegating authorization to an Agent. The user holds an entity certificate and signs the Agent's authorization request using their private key; the gateway verifies the signature using the user's public key.

## Data Structures

### DelegationAuthorization (within certificate)

```asn1
DelegationAuthorization ::= SEQUENCE {
    reason              Reason,                          -- v1.7.1 addition: delegation authorization reason (required)
    requestedLifetime   INTEGER (1..86400),
    timestamp           GeneralizedTime,
    nonce               OCTET STRING (SIZE(32)),
    signatureAlgorithm  AlgorithmIdentifier,
    signatureValue      OCTET STRING
}
```

> v1.7.1: `reason` is at the start of the DA structure (required), same delegation reason as `DelegationAuthTBS.reason`, covered by signature.

### DelegationAuthTBS (Signature Target)

The user's private key signs the DER encoding of `DelegationAuthTBS`:

```asn1
DelegationAuthTBS ::= SEQUENCE {
    version                 INTEGER DEFAULT 1,
    agentId                 UTF8String (SIZE(1..256)),
    principalUid            PrincipalUid,
    reason                  Reason,                          -- v1.7.1 addition: delegation authorization reason (required, covered by signature)
    capabilities            SEQUENCE SIZE(0..256) OF Capability,
    delegationMode          DelegationMode,
    authorizationConstraints [0] EXPLICIT SEQUENCE SIZE(0..32) OF Capability OPTIONAL,
    requestedLifetime       INTEGER (1..86400),              -- SHOULD 3600–86400
    timestamp               GeneralizedTime,                 -- MUST use UTC (Z form)
    nonce                   OCTET STRING (SIZE(32))
}
```

> The `Reason` type definition is in `01-asn1.md` §Reason (added in v1.7.1, both `reasonCode` and `description` MUST be present).

> ⚠️ **v1.6 key note**: `authorizationConstraints` **MUST** be included within the signature coverage (located in `DelegationAuthTBS`).
> This means:
> - The principal, when signing the authorization, is already aware of and agrees to the restrictions in `authorizationConstraints`
> - Any modification to `authorizationConstraints` requires the principal to re-sign
> - During gateway verification, reconstructing the TBS DER and verifying the signature naturally ensures the constraints in the certificate match the signed content
>
> **v1.6.1 note**: `PrincipalAuthorization.authorizationConstraints` and `AIC.authorizationConstraints` are independently checked at their respective semantic layers (see `01-asn1.md` §PA field table), with no subset relationship.
>
> **v1.7.1 note**: `reason` is located in both `DelegationAuthTBS` (after principalUid, required, covered by signature) and `DelegationAuthorization` (at the start of the structure, required, within the certificate) — authorization must always have a reason. See `01-asn1.md` §Encoding Tag Conventions for tag conventions.

> **Lookup note**: Subject lookup/association (cascading revocation, audit, certificate queries) can be done via `principalUid.realm` / `identifier` or database index; signature verification still uses `principalUid.keyHash` as the authoritative source, with authorization and revocation strongly bound to the principal key to prevent identity spoofing.

## Signing Flow

```
① User (principal) constructs DelegationAuthTBS
   ├── agentId:                    Agent's unique identifier
   ├── principalUid:               Principal identity (including KeyHash)
   ├── reason:                     Delegation reason (v1.7.1, required, reasonCode + description, covered by signature)
   ├── capabilities:               Requested capability list
   ├── delegationMode:             authorized / representative
   ├── authorizationConstraints:   Authorization boundary constraints (v1.6, OPTIONAL, covered by signature)
   ├── requestedLifetime:          3600–86400 seconds
   ├── timestamp:                  Current time
   └── nonce:                      32-byte CSPRNG random number

② Sign the DER-encoded DelegationAuthTBS (ECDSA-SHA256 / RSA-SHA256, see §Signing Algorithm Requirements)

③ Construct DelegationAuthorization
   ├── reason:             Same as above (v1.7.1, consistent with TBS)
   ├── requestedLifetime: Same as above
   ├── timestamp:          Current time
   ├── nonce:              Same as above (32 bytes)
   ├── signatureAlgorithm: Algorithm identifier
   └── signatureValue:     Signature value

④ Embed DelegationAuthorization in AIC, submit to CA for issuance
```

## Verification Flow (CA Issuance Phase)

```
① Verify DelegationAuthTBS.timestamp freshness (|now - timestamp| ≤ 30s)
② Verify nonce uniqueness (CA persists used nonces, reject duplicates)
③ Verify delegationAuthorization.signatureValue with principal public key
④ Confirm capabilities are a capability-level subset of PrincipalAuthorization.grants,
   and each capability's parameters do not exceed the corresponding grant's parameters
   boundary (parameter-level subset, if PrincipalAuthorization exists); exceed = reject issuance
⑤ Set certificate NotAfter = now + requestedLifetime (authorization validity = certificate validity)
```

> **① timestamp freshness already implemented (P1-B-13)**: `POST /api/v1/certs` (agent-proxy branch) and `POST /api/v1/aic/issue` validate `|now - timestamp| ≤ da_max_timestamp_skew` before issuance (default 30s, configurable, `"0"` to disable). Together with ② nonce uniqueness, forms the specification's "second line of defense in a short time window" — DA signed but submitted for issuance too late (replay/theft of signature) is rejected (403 `api.da_timestamp_stale`).

## Verification Flow (Gateway Runtime)

See `gateway-core/decision.go:VerifyDelegationAuth`:

```
① Parse certificate AIC, extract DelegationAuthorization
② Locate principal public key via principalUid.keyHash
③ Verify principal certificate chain to trust root
④ Verify signatureValue with principal public key (reconstruct DelegationAuthTBS DER,
   including authorizationConstraints and reason (v1.7.1))
⑤ Cross-check: hashAlgo(Principal certificate.SPKI) == AIC.PrincipalUid.KeyHash
   (current implementation SHA-256)
```

> **The gateway does not check timestamp freshness or Lifetime expiration**. During CA issuance, NotAfter is strictly set to `timestamp + requestedLifetime`; the gateway only needs to rely on standard X.509 validity checking (NotAfter) to complete lifecycle verification.
>
> **Optional hardening (P1-B-13)**: `gateway-core`'s `AdmissionConfig.CheckDAAge` (default false) + `DAAgeMax` (default 30s) can enable gateway-side DA timestamp freshness verification for deployments requiring stricter time windows; lib also provides a standalone `CheckDAFreshness` helper. Disabled by default to maintain consistency with the above design.
>
> **Principal certificate chain and revocation**: The principal certificate chain verification and revocation check (OCSP/CRL) at step ③ MUST be completed by the gateway before calling `VerifyDelegationAuth`; `VerifyDelegationAuth` is only responsible for signature verification and SPKI cross-check. When offline mode skips online revocation checks, high-risk audit MUST be logged (see `03-validation.md` §Verification Sequence).

## Signing Algorithm Requirements

`DelegationAuthorization.signatureAlgorithm` declares the delegation signature algorithm; the verifier MUST only accept the following set:

| Algorithm | OID | Requirement |
|-----------|-----|-------------|
| ECDSA-SHA256 | `1.2.840.10045.4.3.2` | MUST support |
| RSA-SHA256 (PKCS#1 v1.5) | `1.2.840.113549.1.1.11` | MUST support |
| RSA-SHA256 (PSS) | `1.2.840.113549.1.1.10` | MUST support |
| Ed25519 | `1.3.101.112` | MAY (optional implementation) |
| SM2-SM3 | `1.3.6.1.4.1.66257.5.4` | Reserved (Chinese cryptography, not enabled) |

> Signing and verification MUST use the same algorithm; mismatched key type and algorithm (e.g., ECDSA signature with RSA public key) = rejection.

## Nonce Lifecycle

```
At issuance: CA verifies nonce unused → persist to da_nonces table (32B) → write to DelegationAuthTBS
At runtime: Gateway receives connection → signature verification passes = allow
           (nonce replay protection guaranteed at CA issuance time)
           Gateway NonceCache is an optional enhancement (additional replay interception, not relied upon)
```

> **Nonce anti-replay responsibility belongs to CA (already implemented)**: `POST /api/v1/certs` (agent-proxy branch) and `POST /api/v1/aic/issue` call `StoreDANonce` on the 32-byte nonce carried by the client's signature before issuance; the same nonce submitted a second time returns 403 (`api.da_nonce_replayed`). Storage is the `da_nonces` table (migration v29, MySQL `VARBINARY(32)`); when the memory engine is enabled, the engine index is authoritative with asynchronous background persistence; when the engine is disabled, writes go directly to DB. Gateway's `NonceCache` is an optional optimization; in multi-gateway clusters or stateless deployments, it is not relied upon.
>
> **Limitation note**: Gateway `NonceCache` is a **process-local cache** and is not shared across multi-gateway clusters (e.g., multiple `gateway-tcp` instances load balancing). The same nonce replayed to different gateway nodes cannot be detected. This limitation is acceptable because the first line of nonce anti-replay defense is guaranteed by CA issuance-time DB persistence; the gateway cache serves only as additional hardening. Stateless gateway deployments should skip NonceCache.

## RequestedLifetime

- ASN.1 range: `1 ≤ requestedLifetime ≤ 86400` (SHOULD 3600–86400)
- ASN.1 default value: 0 (means "not set")
- Go layer behavior: 0 automatically upgraded to 3600 (1 hour)
- CA issuance policy: `NotAfter = now + min(requestedLifetime, local policy ceiling)`
- Runtime: Gateway only relies on X.509 `NotAfter`, does not check `timestamp + lifetime`

## SEQUENCE Encoding Example

DelegationAuthTBS DER structure field order (Go `encoding/asn1` serialization):

| Order | Field | Description |
|-------|-------|-------------|
| 1 | version | INTEGER DEFAULT 1 |
| 2 | agentId | UTF8String |
| 3 | principalUid | PrincipalUid (SEQUENCE) |
| 4 | reason | Reason (SEQUENCE, required, v1.7.1) |
| 5 | capabilities | SEQUENCE OF Capability |
| 6 | delegationMode | INTEGER (0..1) |
| 7 | authorizationConstraints | [0] EXPLICIT SEQUENCE OF Capability OPTIONAL (v1.6) |
| 8 | requestedLifetime | INTEGER |
| 9 | timestamp | GeneralizedTime |
| 10 | nonce | OCTET STRING (SIZE(32)) |

> Note: Field order must exactly match the ASN.1 definition. Adding or adjusting field order will break verification of all existing signatures. `authorizationConstraints` uses `contextspecific,explicit,tag:0` encoding; OPTIONAL fields do not affect parsing.
>
> v1.7.1: `reason` is at position 4 (after principalUid) and is **required**; its absence causes parsing/signature verification failure.

## Multi-Level Delegation Chain (Implemented — gateway-core 2026-08-07)

> Historical status: Originally reserved as specification FUTURE. Implemented on 2026-08-07 in `gateway-core` with recursive signature verification,
> used for enterprise end-to-end verification use case 8 (Zhang San → Scheduler-A → Worker-B cross-machine recursive verification).

### Architecture

Multi-level delegation reuses the same `DelegationAuthorization` structure, used recursively to form a cryptographic evidence chain verifiable level by level:

```
Principal ──DA──▶ Agent A (chainDepth=0)
                     │
                     ├──DA──▶ Agent B (chainDepth=1)
                     │           │
                     │           ├──DA──▶ Agent C (chainDepth=2)
                     │           └── ...
                     └── ...
```

Each hop's `DelegationAuthorization` has the same structure:

```
Signer (previous-level Agent / Principal) signs DelegationAuthTBS
↓
Receiver (next-level Agent) embeds the previous level's DelegationAuthorization in its own AIC extension
↓
CA verifies signature and issues new certificate (client aic issue --user-cert=<previous level> --user-key=<previous level>)
↓
Gateway/Agent verifies by reverse level-by-level verification: Agent C → Agent B → Agent A → Principal
```

### Implementation (lib code mapping)

| Component | Code | Description |
|-----------|------|-------------|
| Recursive verifier | `DelegationChainVerifier` (decision.go) | `Verify(chain, topPrincipal)` bottom-up level-by-level verification |
| Convenience entry | `VerifyDelegationChain(chain, principal, maxDepth)` | Creates a default verifier |
| Per-level verification | Reuses `VerifyDelegationAuth(aic, signerCert)` | DA signature + SPKI cross-check |
| Chain depth control | `MaxDepth` field + `chainDepth ≤ maxDepth` check | Exceeding = rejection |
| CLI verification | (Not implemented, can be called programmatically via `VerifyDelegationChain()`) | Outputs level-by-level chain verification logs |

The `chain` parameter is a certificate list **from top to bottom** (chain[0]=top-level delegated Agent, chain[len-1]=bottom-level Agent);
the top-level chain[0].AIC.DA is signed by the topPrincipal certificate; each level's AIC DA in the chain is signed by the previous level's certificate.
Each level's AIC issuance must have `PrincipalUid.KeyHash` = the previous level (delegator) certificate SPKI hash —
the client's `principalUidFromCert(cn, userCert)` auto-fills this.

### Principles

- **Reuses existing structures**: `DelegationAuthorization` already covers the signature carrier (TBS), cryptographic algorithm, nonce, lifetime, and all other elements; multi-level delegation **does not require new ASN.1 types**
- **Independent signature per hop**: Each Agent level uses its own private key to sign lower-level authorization information; tampering with any hop causes the entire chain to fail
- **Entire chain verifiable offline**: The gateway holds all certificate chains and can reconstruct TBS level by level → verify signature → check `chainDepth ≤ maxDepth`, with no external service dependency
- **Cryptographically traceable responsibility chain**: Each hop's signature evidence is consolidated in the certificate, auditable to the specific delegator

### Differences from Single-Level Delegation

| Dimension | Single-Level Delegation | Multi-Level Delegation |
|-----------|------------------------|----------------------|
| `chainDepth` | 0 (default) | 1+ |
| `DelegationAuthorization` signer | Principal | Previous-level Agent |
| Verification path | One step | Level by level upward, until Principal |
| Gateway change | — | `DelegationChainVerifier` recursive verification + depth check |

### Security Constraints

- `chainDepth ≤ maxDepth`: Exceeding = rejection (checked at start of `Verify`)
- `maxDepth` is set by the top-level Principal (passed by caller), immutable across the entire chain (covered by ASN.1 signature)
- Agent certificates in the chain MUST be end-entity certificates (cA = FALSE)
- `nonce` replay protection: Each delegation level uses an independent nonce; CA verifies uniqueness at issuance time
