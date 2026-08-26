# AIC × LDAP/AD Identity Source Integration Specification

> ⚠️ **Deferred**: This document covers LDAP/OAuth identity source integration; to be updated after related components are released.

> Status: 🔶 Partially landed (2026-08-24): `bridge-ldap` (`github.com/varwof/bridge-ldap`) + `bridge-oauth` (`github.com/varwof/bridge-oauth`) both implemented, core `identity-user` profile consumed via `IdentitySource` interface
> **FUTURE**: LDAP provisioner (§3.3 P1), directory synchronization (§3.4 P2), group→role mapping (§3.1 P0), status→auto-revocation (§3.2 P0)
> Date: 2026-08-01 (updated 2026-08-24)
> Positioning: Elevate LDAP/AD from "query at issuance time" to **first-class identity source**, composing with AIC/IAM + SPIFFE + OAuth into a complete identity system.
> Related: `11-spiffe-oauth.md` (SPIFFE/OAuth interoperability)

## 0. One Sentence

LDAP/AD has massive market install base (de facto standard for enterprise directories) — it is an **identity source**, not a competitor. AIC/SPIFFE/OAuth handle "how identity is expressed and verified" (pipeline), while LDAP/AD handles "where identity comes from, who is who, which group they belong to" (data source).
The two are complementary as **data source × identity form**, not an either-or choice.

## 1. Three-Layer Identity Architecture: Source → Identity → Form

```
                 ┌─────────────────────────────────────┐
                 │   Identity Source (Source of Truth)  │
                 │   LDAP / AD / FreeIPA (Enterprise Directory)│
                 │   People · Groups · Attributes · Enabled Status · Department OU│
                 └──────────────────┬──────────────────┘
                                    │ ① Directory sync / member query / status
                                    ▼
                 ┌─────────────────────────────────────┐
                 │   Unified Identity (Identity)        │
                 │   PrincipalUid · AgentId · Groups → Roles│
                 │   (AIC's core identity concepts)     │
                 └──────────────────┬──────────────────┘
                                    │ ② Issuance / projection
                                    ▼
        ┌───────────────┬───────────────┬───────────────┐
        ▼               ▼               ▼               ▼
   X.509 View      JWT View       Policy View      Audit View
   AIC Certificate SPIFFE JWT-SVID  RBAC/authorize   Merkle chain
                 + RFC 9068       (Spec 12)        Unified sub
```

**Key insight**: LDAP/AD and OAuth/OIDC decide "who you are" (identity source), while AIC/SPIFFE/OAuth decide "how to prove it" (identity form).
Their responsibilities do not overlap. LDAP/AD is not being replaced but becoming the data foundation of the entire system.

## 2. Current Status Inventory

| Component | Status | Role |
|---|---|---|
| `core/internal/ca/ldap.go` | At issuance, `LookupLDAP` queries directory → fills certificate subject (CN/O etc.) | Source → certificate fields |
| `core/internal/ca/ldap.go` | `CheckMembership` (memberOf group check) | Source → groups → roles |
| `bridge-ldap` satellite (`github.com/varwof/bridge-ldap`) | Standalone HTTP API: `/api/v1/lookup`, `/api/v1/check-membership`, `/api/v1/backends`; multi-backend (AD/OpenLDAP) + hot reload | Remote directory access (network isolation scenarios) |
| Provisioner architecture | mTLS / token / OIDC three authentication methods | Authentication extension point (just add LDAP provisioner) |

**Conclusion**: Query/member check/multi-backend/hot reload **all already exist**. What's missing is connecting LDAP/AD into the **identity source pipeline**
(group→role mapping, status→revocation, authentication→JWT exchange) — these four things are currently disconnected.

## 3. Four Identity Source Pipelines to Complete

### 3.1 Group → Role Mapping (Authorization Source)

Enterprise directory groups (memberOf) are naturally an RBAC role source. Mapping table: `Group DN → Core role`.

```
LDAP Group (memberOf)              Core Role
────────────────────────────────────
CN=PKI-Admins,OU=IT        → admin
CN=PKI-Operators,OU=IT     → ops
CN=Cert-Users,OU=All       → user
```

- Mapping configuration placed in `authz.json` (same source as existing role policies, adding `ou_to_role` or `group_to_role` section)
- At AIC issuance: query user memberOf → map roles → derive `PrincipalAuthorization.grants` /
  capabilities (existing `ProfileAgentProxy` logic deriving from policy can be reused)
- Gateway side similarly: `RunAccessPipeline` RBAC uses group mapping (existing `policy.HasAnyGrant`)

### 3.2 Status → Revocation (Lifecycle)

**Directory status is input to certificate lifecycle**:

- AD `userAccountControl` bits (disabled/locked) → trigger revocation
- User deleted from directory → revoke all their AIC certificates (existing `RevokeByPrincipalUid` SQL fast path, <10ms)
- Offboarding detection = user not in directory or disabled → `revoke-by-principal`

**Implementation**: Directory sync task (periodic polling or webhook) compares directory status with certificate table `principal_uid`/`agent_id`
(DB migration v22 already stored); status change → auto-revocation + audit log.

### 3.3 Authentication → Exchange Unified JWT (LDAP Provisioner)

Add a fourth provisioner (LDAP):

- Username + password → directory bind authentication → query memberOf/attributes → groups→roles → return `AuthResult`
- Reuses `Registry.Authenticate()` unified authentication entry point, alongside mTLS/token/OIDC
- Output: unified JWT (spec `11`) + `/api/v1/session` (Web login scenario, browser does not hold certificate)
- Value: **Web user login extends from "certificate only" to "directory account password"**, covering enterprise existing user habits

### 3.4 Directory Synchronization (Optional, SCIM Alternative)

Lightweight directory synchronization: LDAP → core DB (users/groups/status), serving as a lightweight alternative to SCIM.

- Periodic full comparison or incremental (`uSNChanged`/`modifyTimestamp`)
- Output: role change → reissue AIC / revoke old certificate; offboarding → revoke
- Reuses `bridge-ldap` satellite (`github.com/varwof/bridge-ldap`, already has backend management + hot reload)

## 4. Authentication Method Matrix (Post-Expansion)

| Provisioner | Authentication Credentials | Applicable Scenario | Identity Output |
|---|---|---|---|
| mTLS | AIC certificate | Native App / server-side | X.509 + AIC |
| B2 pass-through | Gateway `X-Client-Cert-DER` | Server-side via gateway | Certificate → AuthUser |
| Token | API token | Script / CI | AuthResult |
| OIDC | Third-party IdP JWT | External login (Google/GitHub) | User identity |
| **LDAP (new)** | Directory account + password | **Enterprise Web login (largest install base)** | Groups→roles → JWT |

> All authentication methods **unified through `Registry` → same RBAC + audit + Merkle pipeline**; adding LDAP does not break
> existing security model (fail-closed, certificates remain the strongest identity anchor).

## 5. Connection with Specs 11/12

- **11 conversion matrix supplement**: `LDAP/AD user → AIC/JWT` = LDAP bind + groups→roles → unified JWT (new row added)
- **12 authorization model supplement**: `subject` can come from directory (`memberOf` group set); `/authorize` decision chain's RBAC
  layer can directly consume directory group mapping
- **11 gap list update**: "Directory lifecycle" changes from "SCIM add-on" to "**built-in: LDAP sync + status→revocation**"
- **04 examples**: LDAP user via directory login → JWT → `/authorize` decision (Web full chain)

## 6. Coverage Enhancement

| Identity Source Dimension | Before | After Built-In |
|---|---|---|
| Directory install base access | Only query fields at issuance | First-class identity source (groups/status/authentication full pipeline) |
| Enterprise Web login | Certificate only | Directory account password + JWT |
| Offboarding/disabling | Manual revocation | Directory status → auto-revocation |
| Groups → roles | No mapping | memberOf → RBAC roles |
| Directory lifecycle | SCIM recommended | Built-in directory sync (SCIM optional) |

## 7. Implementation Path

- **P0**: Group→role mapping (authz.json extension) + status→revocation task (reuse `RevokeByPrincipalUid`)
- **P1**: LDAP provisioner (bind authentication + memberOf → AuthResult → unified JWT)
- **P2**: Directory synchronization (incremental sync + role change reissue) + `/authorize` consuming directory group sets

## 8. Open Decision Points

1. **Where to place group→role mapping**: authz.json extension (recommended, same source) vs standalone `ldap_roles.json`
2. **Authentication binding**: Should LDAP provisioner enforce "directory has this user" (recommended: yes, prevents ghost accounts)
3. **Status sync trigger**: Periodic polling (simple) vs webhook/AD event (real-time, complex)
4. **Revocation policy**: Directory disabled = immediate revocation (strict, recommended) vs mark only for review
