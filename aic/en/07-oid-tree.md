# OID Tree Review: 1.3.6.1.4.1.66257 (2026-08-12, post v1.7.2 slimming)

> Reference: Specification `AIC-Identity & Authorization Technical Specification-1.7.1.md` (§2.2/2.3/10.4/10.5/12 change records), `types/oid.go`, `core/internal/ca/oid.go`.
> Root: 1.3.6.1.4.1.66257 (IANA PEN 66257 — Varwof PKI). Starting from v1.7.2 (2026-08-12), the AIC tree retains only the three core items; non-core items are removed from the specification and carried by implementation or external standards.

---

## I. Official OID Tree (Specification 1.7.2 Current State)

```
1.3.6.1.4.1.66257
│
├── 1  Core Identity & Authorization
│   ├── 1  AIC  ── Agent identity certificate extension
│   │   ├── 1  AgentIdentity       ── Occupied: AIC main extension (agentId, principalUid, delegationMode)
│   │   ├── 2  DelegationAuthorization ── Occupied: Principal signature evidence (.1.1.2; code constant OIDAICDelegationAuthorization, unified from old name UserAuth in v1.7.2)
│   │   └── 4  DelegationDepthControl  ── (FUTURE) Delegation depth control
│   │       ├── 1  chainDepth      ── Current delegation level
│   │       └── 2  maxDepth        ── Maximum allowed delegation depth
│   │
│   ├── 2  PrincipalAuthorization  ── Occupied: Principal authorization declaration (from v1.5, migrated from .1.5)
│   │   └── 4  DelegationPolicy    ── Delegation boundary
│   ├── 3  Capability Scheme Registry ── (Reserved) Scheme registration space (slot reuse: pre-v1.5 OfflineRBAC)
│   ├── 4  Vendor Extension Registry  ── (Reserved) Vendor extension index (slot reuse: pre-v1.5 PrincipalProfile)
│   ├── 5  GatewaySession (historical) ── Pre-v1.5 gateway session extension (migrated to AIC.authorizationConstraints); sub-CA scope extension .1.5.1 still in use
│   └── 6  RenewalToken            ── (Reserved) Authorization renewal token
│
├── 3  National/Industry Certifications (v1.7.2 cleanup, further planning TBD)
│   ├── 1  MarketAccessId          ── Market access container (complete credential)
│   ├── 2  TrustLevel              ── Trust level
│   └── 3  CrossBorder             ── (Reserved) Cross-border mutual recognition
│   (.3.4 EUDIWallet deleted, 2026-08-12)
│
├── 5  Chinese Cryptography Algorithm Identifiers
│   ├── 1  SM2-Signature
│   ├── 2  SM3-Hash
│   ├── 3  SM4-Encryption
│   └── 4  SM2-SM3-Signature
│
└── 6  Certificate Transparency Integration (TransparencyInfo no longer occupies a slot in the AIC tree; CT uses this branch or RFC 6962)
    ├── 1  SCT                     ── SignedCertificateTimestamp
    └── 2  CTLog                   ── CT log identifier
```

## II. v1.7.2 Removed Items

| Original Slot | Original Name | Action | Description |
|:---:|------|--------|-------------|
| .1.1.4 | MarketAccessLite (OIDAICMarketAccess) | Removed | MarketAccess consolidated to branch `.3.1` MarketAccessId; code constant removed (marked DEPRECATED since v1.5) |
| .1.1.10 | AlgorithmSuite | Deleted | v1.5 changelog already marked "deleted"; this cleanup removes residual from tree/mapping table/comparison table; algorithm negotiation follows RFC 5280/TLS 1.3 |
| .1.1.12 | TransparencyInfo | Moved out | CT uses 6.x branch (.6.1 SCT / .6.2 CTLog) or RFC 6962; isKnownExtension updated accordingly |
| .3.4 | EUDIWallet | Deleted | eIDAS 2.0 deferred; branch 3 further planning TBD |
| .1.1.2 | OIDAICUserAuth (old name) | Renamed | Unified as OIDAICDelegationAuthorization (value unchanged) |

## III. AIC Tree (.1.1.x) Slot Occupancy (Post-Slimming)

| Slot | Name | Status |
|:---:|------|--------|
| .1.1.1 | AgentIdentity | Occupied |
| .1.1.2 | DelegationAuthorization | Occupied |
| .1.1.3 | — | Free (unallocated) |
| .1.1.4 | DelegationDepthControl | (FUTURE) Specification reserve, not yet implemented |
| .1.1.5 | UserExtensions | Removed (v1.5) |
| .1.1.6 | — | Free |
| .1.1.7 | — | Free (unallocated) |
| .1.1.8 | — | Free |
| .1.1.9 | VendorRegistry | Removed (v1.5) |
| .1.1.10 | AlgorithmSuite | Deleted (v1.7.2 cleanup) |
| .1.1.11 | SPIFFE-Compatibility | Removed (v1.5) |
| .1.1.12 | TransparencyInfo | Moved out (v1.7.2) |

## IV. Code and Specification Consistency (Aligned 2026-08-12)

- `types/oid.go`: Deleted `OIDAICMarketAccess`, AlgorithmSuite series, `OIDEUDIWallet`; `OIDAICUserAuth` → `OIDAICDelegationAuthorization`.
- `gateway-core/aic.go`: Deleted AlgorithmSuite re-export line.
- `core/internal/ca/oid.go` + `oid_test.go`: Synchronized (submodule, committed 2026-08-12).
- `evidence/e1-aic-size/main.go`: Extension simulation changed to use `OIDAICDelegationAuthorization`.
- Specification 1.7.1 → 1.7.2: Tree/mapping table/known extensions/comparison table/changelog synchronized.
- Pending wiring: DelegationDepthControl (.1.1.4) constants added (`OIDDelegationDepthControl`/`OIDDDCChainDepth`/`OIDDDCMaxDepth`); extension parsing will be wired when P1-11 delegation chain anti-loop/recursive intersection is implemented.

## V. Related Links

- Specification: `AIC-Identity & Authorization Technical Specification-1.7.1.md` §2.2/2.3/3.7/10.4/10.5/12 (v1.7.2)
- Code: `types/oid.go`, `core/internal/ca/oid.go`
- Revision history: `dev-docs/aic/13-revision-history.md` (OID tree slimming, P1-10/13/14/15/16 implementation enhancements)
