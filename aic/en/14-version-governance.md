# Version Governance & Standards Evolution Strategy

> Version: v0.1　Date: 2026-08-06　Status: Policy finalized (not yet executed, to be followed when submitting to IETF in the future)
> Purpose: Resolve the contradiction between "IETF drafts require update every 6 months" vs "AIC specification relatively frozen."

## 1. Core Principles

- **Specification frozen, semantics evolve**: Wire format (ASN.1 core structures) frozen; new semantics evolve through schemeId registry;
- **I-D snapshot system**: Drafts submitted to IETF contain only **frozen snapshots**, not chasing the internal specification's minor improvements;
- **Version decoupling**: Internal semantic version (v1.7.1) and standard version (I-D -00/-01) are independent of each other, not dragging each other down.
- **Explanatory work evolves independently**: Implementation guides, security considerations, deployment profiles, registry entries, and other explanatory content **continuously deepen and update independently without triggering core version changes**; the core specification (ASN.1) maintains minimal necessary content, with explanatory deepening carried by companion documents (such as enterprise profiles, coverage analysis, governance policies, and other numbered series).

## 2. Version System

| Track | Version Form | Constraint | Description |
|---|---|---|---|
| Internal specification | Semantic version vX.Y.Z (currently v1.7.1) | No expiration concept | Single source of truth (dev-docs/aic), own rhythm |
| Standards submission | IETF I-D version (-00/-01/…) | Expires 185 days after publication | Only contains frozen snapshots, independent revision cycle |

## 3. Handling the I-D 6-Month Rule (Choose One)

1. **Refresh version**: Release the next version approximately 5 months before expiration; content limited to clarifications/editorial revisions + registry entry registration, **core ASN.1 unchanged** — 6-month updates shift from "design burden" to "administrative task";
2. **Natural expiration**: Quiet period does not sustain the draft, let the I-D expire (expiration ≠ failure, just disappears from the tracker); resubmit when needed.

## 4. Semantic Evolution Path

- New capability type / constraint type → **schemeId registry evolution**, no modification to I-D core structure;
- Structural changes that are truly necessary (e.g., reserved agentKeyHash) → backward-compatible extension through **AIC/TBS version fields**, after internal specification major version review, then decide whether to enter I-D new version;
- Registry maintained by internal specification; I-D references the registry (namespace/URL), does not inline all entries.

### 4.1 Demand Accommodation Decision Rules (How External Requirements Are Placed)

When external requirements are received, determine in the following order, **defaulting to not modifying the core structure**:

1. **Semantic requirements** (new capability types, new constraint types, new parameter semantics) → registry evolution (new schemeId / capabilityId and parameter definitions), not in structure;
2. **Metadata requirements** (attached attributes, control information, depth/switches, etc.) → `extensions [1]` extension slot (e.g., chainDepth/maxDepth precedent);
3. **Structural requirements** — Only when both "container semantics" and "extension slot" cannot accommodate, and a new top-level field is truly needed → add **optional** field through AIC/TBS version gating (backward compatible, old certificates/old implementations unaffected).

**Criterion**: Before modifying the core structure, must provide written justification that "Capability container semantics and extensions extension slot both cannot express this requirement"; if justification fails, accommodate per 1 or 2.

## 5. Release Discipline

1. Complete intellectual property review before submitting/publishing I-D;
2. Internal specification frozen before first public release (current v1.7.1 is the freeze candidate);
3. Published content must align with the specification version.

## 6. Process When Submitting I-D in the Future

1. Frozen snapshot export (v1.7.1 finalized → `draft-varwof-aic-00`);
2. Refresh -01 approximately 5 months before expiration (clarifications + registry entries);
3. Allow expiration during quiet period, resubmit when needed;
4. Registry evolution independent of I-D revision cycle.

## Appendix: Decision Records

- 2026-08-06: Policy finalized, written to dev-docs/aic as design notes.
