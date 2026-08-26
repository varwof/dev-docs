# Enterprise Privilege Autonomy Deployment Profile

> Version: v1.0
> Date: 2026-07-30
> Corresponds to AIC specification v1.6
> Status: 🟡 PA structure + authz.json implemented; **FUTURE**: `group_to_role` mapping (§3.1), LDAP provisioner (§3.3), directory synchronization (§3.4), status→auto-revocation (§3.2)

Utilizes the `PrincipalAuthorization` extension in the AIC specification to implement enterprise organization-level privilege autonomy, **without involving the Agent delegation chain**. Maps the PKI CA hierarchy to the enterprise organizational structure, where each level's manager has administrative privileges for their level's CA, issuing sub-CA or user certificates downward.

## Hierarchical CA Model

```
Root CA (offline cold backup)
  └── Policy CA (enterprise policy CA, managed by super administrator)
        ├── Finance Department CA (managed by CFO)
        │     ├── Finance employee cert + PrincipalAuthorization
        │     └── ...
        ├── R&D Department CA (managed by CTO)
        │     ├── R&D employee cert + PrincipalAuthorization
        │     └── ...
        └── Marketing Department CA (managed by Marketing Director)
              ├── Marketing employee cert + PrincipalAuthorization
              └── ...
```

| Level | CA | Manager | Responsibility |
|-------|-----|---------|----------------|
| L0 | Root CA | Security Committee | Offline issuance of Policy CA, cold backup |
| L1 | Policy CA | Super administrator (enterprise leader) | Create/delete department CAs, set organization-wide policy baseline |
| L2 | Department CA | Department manager | Issue certificates for department employees, manage department privileges |
| L3 | User certificates | Employees themselves | Hold private keys, certificates contain PrincipalAuthorization |

### Management Workflow

**Super administrator (Policy CA manager):**
- `pki ca init --profile policy-ca --name <department-CA>` — Create department CA (issue certificate + set maxPathLen + validity period)
- `pki ca revoke --serial <SERIAL>` — Revoke department CA (entire department privileges revoked in one step)
- Set organization-wide policy baseline: role definitions, permission templates, CRL cycle in `authz.json`

**Department manager (department CA manager):**
- `varwof-cli issue --ca Finance-CA --profile user` — Issue employee certificates
- `pki revoke --serial <SERIAL>` — Revoke employee certificates (departure/privilege change)
- Assign roles and permissions to employees via `PrincipalAuthorization`

**Employees:**
- Hold their own key pair (private key is never generated or stored on the server)
- Certificate contains `PrincipalAuthorization`; gateway/application layer parses and executes directly
- No need to query external permission systems; the certificate carries everything

## Permission Structure

The `PrincipalAuthorization` extension in the user certificate carries permission information:

```asn1
PrincipalAuthorization ::= SEQUENCE {
    version                     INTEGER DEFAULT 1,
    grants                      SEQUENCE OF Capability,
    authorizationConstraints    [0] EXPLICIT SEQUENCE SIZE(0..32) OF Capability OPTIONAL,
    delegationPolicy            [1] EXPLICIT DelegationPolicy OPTIONAL,
    extensions                  [2] EXPLICIT Extensions OPTIONAL
}
```

### Role Design

Roles are defined in `authz.json`, isolated by department; certificate OU is mapped to roles via `ou_mapping`:

```json
{
  "roles": {
    "Finance/Accountant": {
      "grants": ["finance:query:invoice", "finance:report:monthly"],
      "profiles": ["finance-acc"]
    },
    "Finance/Director": {
      "grants": ["finance:*:*", "admin:finance-ca:*"],
      "profiles": ["finance-dir"]
    },
    "R&D/Engineer": {
      "grants": ["code:read:repo", "code:pr:create"],
      "profiles": ["rd-eng"]
    },
    "R&D/CTO": {
      "grants": ["code:*:*", "admin:rd-ca:*"],
      "profiles": ["rd-cto"]
    },
    "SuperAdmin": {
      "grants": ["admin:*:*"],
      "profiles": ["m-superadmin"]
    }
  },
  "ou_mapping": {
    "FinanceAcc": "Finance/Accountant",
    "FinanceDir": "Finance/Director",
    "RDEngineer": "R&D/Engineer",
    "RDCTO": "R&D/CTO",
    "SuperAdmin": "SuperAdmin"
  }
}
```

> **Note**: Roles in `authz.json` are flat definitions (no inheritance); each role independently lists its `grants`.
> At issuance time, the policy engine writes the role's `grants` into `PrincipalAuthorization`.
> The mapping between roles and certificate OU is implemented through the `ou_mapping` section.

### Permission Granularity

Expressed through `Capability`'s `schemeId:capabilityId:parameters` triple:

| Expression | Meaning |
|------------|---------|
| `finance:query:invoice` | Finance department invoice query |
| `finance:*:*` | All finance department operations |
| `code:read:repo` | Code read-only |
| `admin:finance-ca:issue` | Finance department CA issuance authority |
| `admin:*:*` | All administrative privileges |

## Permission Changes

### Scenario: Employee Transfer

```
Employee transfers from Finance/Accountant → R&D/Engineer

Audit trail:
  1. CFO revokes old certificate (CRL issued + OCSP immediate effect)
  2. CTO issues new certificate (with new department PrincipalAuthorization)
  3. Old certificate added to CRL, new certificate starts being used
```

Timeline:

| Step | Action | Timing |
|------|--------|--------|
| T+0 | CFO `pki revoke --serial <old cert>` | Effective after next CRL publication (default within 1h) |
| T+0 | CTO `pki issue --ca R&D-CA --profile user` | Immediate |
| T+0 | Employee obtains new certificate + private key | Immediate |
| T+5min | CRL refreshes, old certificate invalidated network-wide | CRL cache TTL |

> OCSP response takes effect immediately; configuring both OCSP + CRL is recommended for dual protection. CRL serves as offline backup.

### Scenario: Temporary Task

Use short-lived certificate, validity ≤ 1h:

```bash
# Department manager issues short-term certificate (--validity unit: days, 0 means default)
varwof-cli issue --ca R&D-CA \
  --profile user \
  --validity 1 \
  --cn "Temporary audit task" \
  --pa '["audit:read:log", "audit:export:report"]'
```

Certificate automatically expires after task completion without revocation. Matches `DelegationAuthorization.requestedLifetime` mechanism.

### Scenario: Employee Departure

1. Department manager revokes all certificates for that employee (`pki revoke --principal-uid <uid>`)
2. CRL + OCSP takes effect immediately or with delay
3. Audit log records the revocation operation and operator

### Scenario: Employee Privilege Reduction (Runtime PA Refresh, Immediate Effect)

After the principal revokes and re-issues (**same key pair**, **fewer grants**), the old AIC certificate remains cryptographically valid
(`principalUid.keyHash` unchanged), but permissions should shrink immediately. Implementation (gateway-core runtime
PA refresh):

- `CheckAdmission` in representative mode, before P∩C intersection, uses the principal's **current** certificate (`UserCert` or credential bundle
  `Principal`, keyHash cross-verified as the same subject)'s `PrincipalAuthorization` as authoritative
  P_grants;
- Out-of-bounds capabilities from the old AIC are removed from `EffectiveCaps` — **no need to reissue agent certificate**, nor wait for
  CRL/OCSP propagation (effective as soon as credential bundle/parser obtains the new certificate);
- Revocation path: core CLI `revoke` / API `POST /api/v1/cert/{ca}/{serial}/revoke`
  (supports cascading by PrincipalUid) / client `revoke`; cascading revocation is a stronger mechanism (agent
  certificate directly revoked), PA refresh is a "certificate still valid, permissions shrink" mechanism, the two complement each other.
- Verification: `TestPrincipalDowngradeRevokesAgentPermissions` (C1→C2 same key, one fewer permission →
  old AIC's INSERT disappears from EffectiveCaps).

### Auxiliary Tool: Certificate Lookup by Public Key

Find all certificates for the same key pair via SPKI hash (current implementation SHA-256):

- **API**: `GET /api/v1/cert/by-key?hash=<hex>`
- **CLI**: `client find-by-key --key <path>` / `--cert <path>` / `--hash <hex>`
- **Use case**: Identify old certificates for the same key pair during certificate renewal, troubleshoot duplicate issuance, enumerate associated certificates before revocation

See `dev-docs/api/core.md` §Certificate Retrieval.

## Relationship to Agent Delegation

This profile is **completely independent** of AIC's Agent delegation functionality:

| Dimension | Enterprise Privilege Autonomy | Agent Delegation |
|-----------|------------------------------|------------------|
| Certificate holder | Enterprise employees (natural persons) | AI Agent / automated programs |
| Permission carrier | `PrincipalAuthorization` | `AIC.capabilities` + `DelegationAuthorization` |
| Authorization mode | Direct CA issuance | Principal signed delegation |
| Multi-level | Organizational CA hierarchy | Delegation chain (FUTURE) |
| Optional | All user certificates contain it | Only Agent certificates need it |

Both can be deployed simultaneously in the same PKI. Employee certificates use enterprise privilege autonomy; Agent certificates use delegation authorization. Same Root CA and Policy CA, different profiles.

```
Root CA
  └── Policy CA
        ├── Finance Department CA ──── Finance employee certificates (enterprise privilege autonomy)
        ├── R&D Department CA ──── R&D employee certificates (enterprise privilege autonomy)
        └── Agent CA ──── Agent certificates (delegation authorization)
```

## Security Recommendations

1. **Department CA lifecycle**: Department CA certificate validity recommended at 2-5 years; automatic renewal reminder 30 days before expiry
2. **User certificate validity**: Default 7-30 days (short-lived certificates reduce revocation pressure); upper limit 90 days
3. **Revocation timeliness**: OCSP recommended with 5-minute cache; CRL published daily; **high-security scenarios** OCSP must-staple
4. **Super administrator privilege separation**: Policy CA private key encrypted + systemd credential injection + dual-person approval with cardholder
5. **Audit**: All issuance/revocation operations recorded in audit log; TSA timestamp signatures ensure tamper-proofing
6. **Key ownership**: Employee certificate private keys MUST be generated client-side; CA never has access to plaintext private keys
