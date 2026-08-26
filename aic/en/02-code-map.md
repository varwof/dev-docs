# Go Struct ↔ ASN.1 Mapping & Code Location

> Specification v1.7.1 (code aligned, closed out 2026-08-05).

> 2026-08-24 alignment notes
> - Current module names: `types`, `gateway-core`, `core` (old names `pki-types` / `pki-gateway-lib` / `pki-core` are deprecated).
> - **AIC-JWT**: claims/JWS/capability matching/constraints/key binding/11-step verification are in `types/aicjwt/`
>   (`github.com/varwof/types/aicjwt`); the standalone reference repository aic-jwt is a wrapper layer + OAuth scenario tests.
> - **SPIFFE**: `types/aic.go` (Build/Validate/AddSAN), `gateway-core/spiffe.go` (parsing/admission),
>   `core/internal/ca/sign.go` (SAN dual-write), `core/internal/serve/api_ops.go` (is_spiffe parameter).
> - **OAuth identity source**: `bridge-oauth/` (bridge service), `core/internal/ca/identity.go`
>   (`IdentitySourceOAuth`, password grant + userinfo).
> - Constraint schemeId whitelist: `varwof/constraint-v1` (recommended by specification), `constraint`, `constraint-v1` (backward compatibility); AIC/PA constraint count limit 32 entries.
>
> ✅ v1.7.1 completed:
> - `Reason` added (DA first position, TBS after principalUid), TBS reconstruction includes reason
> - All structure OPTIONAL field tag renumbering (AIC constraints→[0], extensions→[1]; PA constraints→[0], delegationPolicy→[1], extensions→[2]; DelegationPolicy.maxSessionHours→[0])
> - `DelegationMode` / `DelegationModeEnum` changed to INTEGER (0..1)
> - `PrincipalUid.hashAlgo` changed to `AlgorithmIdentifier` value type (`[0] EXPLICIT OPTIONAL`, defaults to SHA-256 when omitted)
> - `AIC.delegationAuthorization` semantically required (Go retains omitempty for marshalability, `BuildAIC`/`ParseAIC`/`ValidateAIC` enforced)
> - keyHash = hashAlgo(SPKI): `ValidatePrincipalUidKeyHash` dispatches by algorithm; constraint schemeId whitelist `{constraint, constraint-v1, varwof/constraint-v1}`; non-SHA-256 explicitly reports "unsupported"

> Known limitation: CA issuance-phase **parameter-level subset validation** (`C_agent.parameters ⊆ P_grants.parameters`) is not yet implemented. It applies at the capability layer and MUST NOT be applied to the constraint layer; it is planned for a future release.

## gateway-core (Shared Library)

| File | Go Type | Corresponds to ASN.1 | Description |
|------|---------|---------------------|-------------|
| `aic.go` | `AIC` | AIC SEQUENCE | Core structure, including authorizationConstraints (v1.7.1 constraints→[0], extensions→[1]) |
| `aic.go` | `PrincipalUid` | PrincipalUid | String/ParsePrincipalUid/MakePrincipalUidFromCert + HashAlgoOID; hashAlgo is AlgorithmIdentifier value type |
| `aic.go` | `DelegationAuthorization` | DelegationAuthorization | reason(first position) + requestedLifetime + timestamp + nonce + signatureAlgorithm + signatureValue (v1.7.1) |
| `aic.go` | `Capability` | Capability | schemeId + capabilityId + parameters (reused as constraint container) |
| `aic.go` | `ExtField` | ExtField | AIC extension slot entry |
| `aic.go` | `AlgorithmIdentifier` | AlgorithmIdentifier | algorithm OID + parameters |
| `aic.go` | — | DelegationMode | Go const DelegationAuthorized(0) / DelegationRepresentative(1) |
| `types/user_permission.go` | `PrincipalAuthorization` | PrincipalAuthorization | grants + authorizationConstraints([0]) + delegationPolicy([1]) + extensions([2]) (v1.7.1) |
| `types/user_permission.go` | `DelegationPolicy` | DelegationPolicy | version + maxAgents + allowedMode + maxSessionHours([0] value int) |
| `types/aic.go` | `DelegationAuthTBS` | DelegationAuthTBS | Signature-covered structure, reason after principalUid, authorizationConstraints→[0] |
| `types/aic.go` | `ValidateAIC` / `ValidatePrincipalUidKeyHash` | — | v1.7.1 validation (R1–R5, V6, V8, V10/V15, V16, nonce 32B, constraint whitelist) |
| `decision.go` | `VerifyDelegationAuth` | — | TBS reconstruction (including reason) + signature verification + SPKI hash cross-check (ECDSA/RSA-SHA256/PSS) |
| `decision.go` | `CheckAuthorizationConstraints` | — | v1.6 offline verification of CIDR/concurrency/time window |
| `pipeline.go` | `RunAccessPipeline` | — | 9-step unified admission pipeline (v1.6 includes constraint checks) |
| `plugin.go` | `PluginRegistry` | — | Capability Scheme plugin engine |

## core

| File | Go Type | Corresponding OID | Description |
|------|---------|-------------------|-------------|
| `internal/ca/oid.go` | OID constants | Full OID tree | Unified OID definitions |
| `internal/ca/aic.go` | AIC issuance structure | `.1.1` | BuildAIC (including V10/V15/V16/nonce validation) + ParseAIC (reports error on DA absence) + ValidatePrincipalUidKeyHash + SPKIHash |
| `internal/ca/principal_auth.go` | PrincipalAuthorization / DelegationPolicy | `.1.2` | v1.7.1 three tags ([0]/[1]/[2]) + maxSessionHours [0] value type |
| `internal/ca/sign.go` | ProfileAgentProxy | — | Issues AIC certificates |
| `internal/serve/api_ops.go` | API handlers | — | AIC issuance (DA required with authorization 400), revocation API |
| `internal/serve/rbac.go` | authenticate + authFromAIC | — | Role extraction |

## gateway-{tcp,http,udp}

| File | Function | Description |
|------|----------|-------------|
| `gateway.go` | NewGateway | Unified constructor, integrates all lib components |
| `mapping.go` / `proxy.go` | Data plane | Calls RunAccessPipeline for admission |

## OID → Code Mapping

| OID | Name | Definition Location | Parsing Location |
|:---:|------|--------------------|------------------|
| `.1.1` | AIC | `core/internal/ca/oid.go` | `gateway-core/aic.go:ParseAIC` |
| `.1.1.1` | AgentIdentity | `core/internal/ca/oid.go` | Embedded in AIC |
| `.1.1.2` | DelegationAuthorization | `core/internal/ca/oid.go` | `gateway-core/decision.go:VerifyDelegationAuth` |
| `.1.2` | PrincipalAuthorization | `core/internal/ca/oid.go` | `gateway-core/decision.go` |
| `.1.2.4` | DelegationPolicy | `core/internal/ca/oid.go` | `gateway-core/decision.go` |
| `.1.6` | RenewalToken | `core/internal/ca/oid.go` | Reserved |
| `.3.1` | MarketAccessId | `core/internal/ca/oid.go` | Reserved |
| `.5.1` | SM2-Signature | `core/internal/ca/oid.go` | core Chinese cryptography |
| `.6.1` | SCT | `core/internal/ca/oid.go` | CT logs |

## ACL

The following features were removed from Core in v1.5; corresponding OIDs are retained but no longer parsed:

| OID | Removed Item | Replacement |
|:---:|-------------|-------------|
| `.1.1.4` | MarketAccessLite | Merged into `.3.1` |
| `.1.1.5` | UserExtensions | AIC built-in extensions slot |
| `.1.1.9` | VendorRegistry | Moved to `.1.4` |
| `.1.1.11` | SPIFFE-Compatibility | Optional Profile |
| `.1.3` | OfflineRBAC | Capability Scheme |
| `.1.4` | PrincipalProfile | Directory service |
| `1.2` → `1.5` | PrincipalAuthorization OID migration | OID from `.1.5` → `.1.2` |
