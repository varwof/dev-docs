# ValidateAIC Validation Rules

> Code: `gateway-core/aic.go:ValidateAIC`

Validation is called after `ParseAIC` and before `CheckAdmission`.

## Core Validation Items

| # | Check | Rule | On Violation |
|---|-------|------|--------------|
| 1 | Capability count limit | `len(capabilities) ≤ 256` | Reject |
| 2 | schemeId length | `1 ≤ len(schemeId) ≤ 128` | Reject |
| 3 | capabilityId length | `1 ≤ len(capabilityId) ≤ 256` | Reject |
| 4 | parameters length | `len(parameters) ≤ 4096` | Reject |
| 5 | Extensions unknown critical | Unknown OID with critical=TRUE | Reject |
| 6 | principalUid.realm length | `1 ≤ len(realm) ≤ 128` (ASN.1 `SIZE(1..128)`) | Reject |
| 7 | principalUid.identifier length | `1 ≤ len(identifier) ≤ 256` (ASN.1 `SIZE(1..256)`) | Reject |
| 8 | keyHash length | Specification `1 ≤ len(keyHash) ≤ 64` (`SIZE(1..64)`, only supports hash algorithm families with output length ≤64 bytes); must equal the output length declared by `hashAlgo` — current implementation supports full SHA-2/SHA-3 family (SHA-256=32/SHA-384=48/SHA-512=64/SHA3-256=32/SHA3-384=48/SHA3-512=64 bytes); length mismatch or algorithms like SM3/BLAKE2/BLAKE3 requiring external dependencies explicitly report unsupported (P1-A-12) | Reject |
| 9 | nonce length | `len(nonce) == 32` | Reject |
| 10 | requestedLifetime range | `1 ≤ lifetime ≤ 86400` (SHOULD ≥ 3600) | Reject |

> Note: The `0 → 3600` upgrade only exists at **API input layer normalization** (when caller passes 0, treated as default 3600); the wire value encoded into TBS/DA must already be within 1..86400 range, ASN.1 defines it as `INTEGER (1..86400)` with no DEFAULT 0.
| 11 | Capabilities must not use constraint schemeId | Each MUST NOT have `schemeId = "varwof/constraint-v1"` | Reject |
| 12 | Non-empty authorization | `capabilities` must not be empty (at least one entry, CA issuance policy MUST enforce); `authorizationConstraints` may be empty (empty = no restrictions) | Reject issuance |

## authorizationConstraints Validation (v1.6)

### AIC-Level Constraint Validation

| # | Check | Rule |
|---|-------|------|
| C1 | Constraint count limit | `len(constraints) ≤ 32` |
| C2 | schemeId whitelist | Each MUST be `"varwof/constraint-v1"` (recommended by specification), `"constraint"` or `"constraint-v1"` (backward compatibility); other values rejected |
| C3 | capabilityId identification | SHOULD be one of `network:cidr` / `session:max-concurrent` / `time:window` / `geo-fence`; unknown types by default **log audit warning and ignore** (does not block business); if ops configures `StrictConstraints: true`, then reject |
| C4 | parameters JSON parseable | MUST be valid JSON (`json.Valid`), only for constraint type (varwof/constraint-v1 whitelist) parameters — built-in constraint formats are defined by this specification; business capabilities (non-constraint schemeId) parameters are opaque byte strings, encoding defined by schemeId scheme (JSON recommended, CBOR/ASN.1/binary etc. allowed) |
| C5 | Single parameters size | ≤ 512 bytes (after UTF-8 encoding) |
| C6 | capabilityId non-empty | MUST be non-empty string |

### PA-Level Constraint Validation (v1.6.1)

PA's `authorizationConstraints` follows the same format rules as AIC:

| # | Check | Rule |
|---|-------|------|
| P1 | Constraint count limit | `len(constraints) ≤ 32` |
| P2 | schemeId whitelist | Each MUST be `"varwof/constraint-v1"` (recommended by specification), `"constraint"` or `"constraint-v1"` (backward compatibility); other values rejected |
| P3 | capabilityId non-empty | MUST be non-empty string |
| P4 | parameters JSON parseable | MUST be valid JSON |
| P5 | Single parameters size | ≤ 512 bytes |
| P6 | Runtime check | PA constraints encountering unsupported constraint types **degrade to audit warning and ignore** (same lenient policy as AIC) |

PA constraints execute **independently** of AIC constraints: when accessing directly (without AIC), PA constraints are the only constraints; when accessing through delegation, PA and AIC constraints are independently checked at their respective layers, with no subset relationship.

> **Default lenient (Forward-Compatible)**: Unknown constraint types are ignored, ensuring new constraints can be gradually rolled out in mixed old/new gateway deployments. Strict mode is controlled by ops configuration switch.

### Constraint Parameter Validation Details

#### `network:cidr`

Supports two JSON forms (gateway accepts both):

```json
["10.0.0.0/8", "192.168.0.0/16"]
```

```json
{"cidrs": ["10.0.0.0/8", "192.168.0.0/16"]}
```

- MUST be JSON array, or `{"cidrs": [...]}` object
- Each item MUST be a valid CIDR string
- Empty list = no restrictions (equivalent to no such constraint)
- Requires the gateway to provide the connection peer IP (`ClientIP`); constraint is skipped when IP is empty (cannot evaluate source address)

#### `session:max-concurrent`

```json
{"max": 5}
```

- `max` MUST be an integer, 1 ≤ max ≤ 1024
- Checked by the gateway connection tracker; skipped during constraint evaluation phase (placeholder type)

#### `time:window`

```json
{"start": "22:00", "end": "06:00"}
```

```json
{"start": "09:00", "end": "18:00", "tz": "Asia/Shanghai"}
```

- `start` / `end` MUST be in `HH:MM` format (00:00–23:59)
- `tz` is an IANA timezone name (optional): window times are interpreted per this timezone and automatically converted at evaluation time; defaults to **UTC** evaluation (backward compatibility)
- Cross-day windows (start > end) indicate spanning days (e.g., 22:00–06:00)
- Window includes the start point but excludes the end point (09:00–18:00 exits the window at exactly 18:00)

#### `geo-fence`

Supports two forms: inline table and external resolver:

```json
{"resolver": "inline", "regions": {"CN-SHA": ["10.0.0.0/8", "192.168.0.0/16"]}}
```

```json
{"resolver": "ip2region", "regions": ["CN-SHA", "CN-BJS"]}
```

- `resolver` is the region resolver name: `inline` (default, zero external dependency, regions is a region→CIDR inline table, IP matching any CIDR belongs to that region) or an external resolver
- External resolvers must first be registered at the gateway (`RegisterGeoResolver`, e.g., ip2region); **unregistered resolver evaluation failure = reject connection (fail-closed), not silent pass**
- `regions` is the set of allowed region identifiers; client IP resolved region identifier must match
- Requires the gateway to provide the connection peer IP; constraint is skipped when IP is empty

## Reason Validation (v1.7.1)

`DelegationAuthorization.reason` and `DelegationAuthTBS.reason` reuse the same `Reason` structure (defined in `01-asn1.md` §Reason). `reason` is a **required** field (authorization must always have a reason), for descriptive purposes (audit/display), does not participate in permission decisions; validation failure only rejects the certificate/signature, does not affect authorization intersection calculation.

| # | Check | Rule |
|---|-------|------|
| R1 | `reasonCode` present | MUST be present and non-empty (UTF8String) |
| R2 | `description` present | MUST be present and non-empty (UTF8String) |
| R3 | `reasonCode` value style | SHOULD be SCREAMING_SNAKE (controlled vocabulary, e.g., `SCHEDULED_MAINTENANCE`) |
| R4 | `reasonCode` length | MUST ≤ 64 characters, should be as short as possible |
| R5 | `description` length | MUST ≤ 512 characters |

## Extensions Known OID List

`isKnownExtension` recognizes the following OIDs:

| OID | Name |
|:---:|------|
| `.1.2` | PrincipalAuthorization |
| `.3.1` | MarketAccessId |

`.1.1.1` AgentIdentity and `.1.1.2` DelegationAuthorization are embedded fields of the AIC
extension itself (not standalone extensions), so they are intentionally absent from this list.

Other OIDs with `critical=true` will cause rejection.

> AIC and PrincipalAuthorization extensions themselves MUST be non-critical (`critical=TRUE` is rejected as unknown extension), ensuring non-AIC-aware systems can safely ignore them.

## AdmissionConfig Options

`AdmissionConfig` provides finer-grained runtime admission control:

| Option | Default | Description |
|--------|---------|-------------|
| `RequireAIC` | false | Reject connections without AIC extension |
| `RequiredProtocol` | "" | Require Agent to have specified SchemeId |
| `RequiredCapabilities` | nil | Require Agent to have all specified capabilities; matching is glob wildcard (`MatchCapability`), AIC declarations (bare capabilityId or `schemeId:capabilityId`) serve as patterns, declaration-side wildcards can cover detail requirements — e.g., declaring `SELECT:*` (full name `mysql:SELECT:*`) covers requirements `mysql:SELECT:*` / `mysql:SELECT:/api/tables`, but `mysql:INSERT:*` / `http:GET:/admin` is rejected |
| `DisallowRepresentative` | false | Reject representative mode |
| `RequireUserAuth` | false | Require DelegationAuthorization signature verification to pass |
| `EnforceCapSizeConstraints` | false | Validate Capability field lengths |
| `NonceCache` | nil | Nonce replay protection cache (nil=skip) |
| `EnforceSize32` | false | Validate nonce is 32 bytes |
| `EnforceConstraints` | false | v1.6 whether to enforce authorizationConstraints; both PA-level and AIC-level are controlled by this switch |

### EnforceConstraints Behavior

| Constraint Type | Check Logic | On Violation |
|----------------|-------------|--------------|
| `network:cidr` | Connection peer IP is in any CIDR | Reject |
| `session:max-concurrent` | Current Agent active connection count has reached the limit | Reject |
| `time:window` | Current time is within the window (converted per tz, default UTC) | Reject |
| `geo-fence` | Connection peer IP resolved region identifier is in the allowed set | Reject |
| Unknown type | Log audit warning and ignore (lenient); strict mode can reject | Per configuration |

## Verification Sequence (v1.6.1 Clarifies Dual-Level Constraints)

After the gateway completes the TLS handshake, verification is executed in the following order:

```
1. Certificate chain verification                    ← Standard X.509 path building
   ├── Network reachable: MUST validate OCSP Stapling or CRL; reject if not passed
   └── Network unreachable/offline mode: skip online revocation check (fail-open),
       log high-risk audit; **enforce** remaining certificate validity ≤ 1h
       (G2(b) implemented: when ocsp_fallback=allow, gateway injects
       OfflineMaxCertLifetime=1h, exceeding = reject)
2. Parse AICExtension                                ← Extract identity + capabilities + constraints
3. Verify DelegationAuthorization                    ← Principal signature verification + SPKI hash cross-check
4. Check chainDepth ≤ maxDepth (FUTURE)              ← Multi-level delegation chain depth control, single-level deployment can omit
5. **Check PA.authorizationConstraints**             ← v1.6.1, PA constraints independent of AIC constraints
6. Check AIC.authorizationConstraints               ← Execute first, low-cost fast rejection
   └── Runtime constraint checks (IP/time/region/session:max-concurrent)
7. Check capabilities                                ← Business capability matching (glob wildcard: declarations as patterns covering requirements, see `RequiredCapabilities`)
8. Apply Gateway Policy                              ← Runtime policies (timeout/retry/rate-limiting/routing)
9. Allow/Reject
```

**Rationale**: PA constraints and AIC constraints are two independent check layers, acting on the authorization boundary and execution boundary respectively, with no subset relationship.

## Multi-Constraint Combination Logic

When a certificate contains multiple `authorizationConstraints`:

> The gateway **MUST** require all constraints to be simultaneously satisfied (**AND logic**). If any single constraint is not satisfied, the request is rejected.

Example:

```json
{
  "authorizationConstraints": [
    {"schemeId": "constraint", "capabilityId": "time:window",
     "parameters": "{\"start\":\"22:00\",\"end\":\"06:00\"}"},
    {"schemeId": "constraint", "capabilityId": "network:cidr",
     "parameters": "[\"10.0.0.0/8\"]"}
  ]
}
```

→ Must satisfy both "night shift time" **and** "internal network IP" to be allowed.

## Decision Model

```
AIC.capabilities: Agent's capability declarations
AIC.authorizationConstraints: Agent-level authorization boundary constraints (v1.6)
PrincipalAuthorization.grants: Principal's allowed capability grants
PrincipalAuthorization.authorizationConstraints: Principal-level authorization boundary constraints (v1.6.1, independent of AIC constraints)
T_policy: Gateway local policy

EffectiveCapability = P_grants ∩ C_agent ∩ T_policy
EffectiveConstraint = PA_constraints ∩ C_constraint ∩ T_constraint_policy

direct mode (no AIC):     audit actor = principal, permission boundary = PA ∎ PA_constraints
authorized mode (has AIC): audit actor = agentId, permission boundary = C_agent ∩ PA_collected ∩ T_policy
representative mode:      audit actor = principalUid, permission boundary = P ∩ C ∩ T
```

## Certificate Size Constraints (v1.6)

| Certificate Type | Recommended Limit | Hard Limit | Description |
|-----------------|-------------------|------------|-------------|
| All-protocol safety limit | 12KB | 16KB | Compatible across all four gateways |
| Handshake certificate | 8KB | 16KB | AIC certificate used for mTLS handshake; exceeding 16KB causes QUIC handshake failure |
| Full authorization certificate | 64KB | 128KB | Contains all capabilities + constraints + extensions, application layer transport |
| Single Capability parameters | 512B | 4096B | 05-capability.md §Parameters |

Certificates exceeding the hard limit MUST be rejected by the gateway.

## Delegation Depth Control (FUTURE)

When the certificate extension contains `DelegationDepthControl`:

| # | Check | Rule |
|---|-------|------|
| Φ1 | chainDepth ≤ maxDepth | `chainDepth` MUST ≤ `maxDepth`; exceeding = reject connection |
| Φ2 | chainDepth continuity | When the Nth-level Agent delegates to a lower level, it sets `chainDepth = current value + 1` |
| Φ3 | maxDepth immutability | `maxDepth` is set by the top-level Principal across the entire delegation chain; lower levels must not tamper with it |

> FUTURE: Current gateway only supports single-level delegation (chainDepth = 0); the above rules for multi-level delegation chains are specification reserves.
