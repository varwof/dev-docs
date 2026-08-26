# Dual-Certificate Deployment: Handshake Certificate + Authorization Certificate

> Version: v1.1 (2026-08-16, G4 strong binding)
> Status: FUTURE — Deployment strategy design document (`VerifyBelongTo` implemented, gateway data plane wiring not yet implemented)

## Background

AIC certificates may carry a large number of Capabilities (tens to hundreds) and AuthorizationConstraints (multiple IP/region/time windows), causing certificate size to potentially balloon from a few KB to tens of KB.

The QUIC protocol imposes a ~16KB hard limit on the certificate chain during the TLS handshake phase. Exceeding this value causes immediate handshake failure.

## Solution: Split One Certificate into Two

The AIC protocol remains unchanged; only the certificate content is split into two certificates, presented at different phases:

| Certificate | Presentation Timing | Content | Typical Size |
|-------------|--------------------|---------|--------------| 
| **Handshake Certificate** | mTLS/DTLS/QUIC handshake | `agentId` + `principalUid` + `delegationMode` + `DelegationAuthorization` (capabilities at least one entry, specific placeholder capabilities defined by deployment per registry; authorizationConstraints may be empty) | ~2-4KB |
| **Authorization Certificate** | After TLS handshake completion, application layer send | Complete AIC: `capabilities` + `authorizationConstraints` + `DelegationAuthorization` + extension information | Potentially 20-50KB |

### Execution Flow

```
Agent                                    Gateway
  │                                          
  │ ① Handshake cert (agentId + principalUid + DA) 
  │──────────────────────────────────────────▶  TLS handshake (<16KB ✅)
  │                                          ② Verify handshake cert chain
  │                                          Establish secure connection
  │
  │ ③ Application layer sends authorization cert (complete AIC, including DA)  
  │──────────────────────────────────────────▶  Application layer (no size limit ✅)
  │                                          ④ Verify authorization cert (same trust chain)
  │                                            Extract capabilities + constraints
  │                                            Execute authorization decision
  │ ⑤ Business data                               
  │◀────────────────────────────────────────▶
```

### Why This Bypasses the QUIC 16KB Limit

The QUIC 16KB limit only applies to the **Certificate message during the TLS handshake**. Data sent via the application layer (QUIC stream) is not subject to this limit. Placing the authorization certificate after the handshake completely circumvents this hard limit.

## Credential Bundle Integration

The dual-certificate approach naturally fits the Credential Bundle concept:

```
Credential Bundle
├── Handshake Certificate    — Identity proof, TLS layer
├── Authorization Certificate — Permission manifest, application layer
└── CA Chain                 — Trust chain
```

Both certificates are issued by **the same CA** with a consistent trust chain; verification logic remains unchanged.

## Three Methods for Authorization Certificate Delivery

### Method A: Agent Proactive Push (Recommended)

```
Agent → Gateway: Handshake certificate (mTLS)
Agent → Gateway: Authorization certificate (application layer header/frame)
```

- After handshake completion, the Agent immediately sends the authorization certificate at the application layer
- Gateway caches the authorization certificate for subsequent requests
- Lowest latency, completed in one interaction

### Method B: Gateway On-Demand Pull

```
Agent → Gateway: Handshake certificate (mTLS)
Gateway → pki-core: GET /api/v1/cert/by-key?hash=<agent-spki>
pki-core → Gateway: Authorization certificate
```

- Agent only needs to send the handshake certificate
- Gateway retrieves the complete authorization from pki-core based on the handshake certificate's SPKI hash
- Use case: Agent minimal deployment, does not want to carry large certificates

### Method C: Lazy Loading (On-Demand Pull)

```
Agent → Gateway: Handshake certificate (mTLS)
Agent → Gateway: Send business request
Gateway: Discovers missing authorization certificate → requests from Agent
Agent → Gateway: Authorization certificate
```

- Gateway only requests the authorization certificate when needed
- Suitable for one-time operations (e.g., token exchange)

## Gateway Processing Logic

```go
func handleQUICConnection(conn quic.Connection, handshakeCert *x509.Certificate) error {
    // 1. Verify handshake certificate (TLS layer already complete)
    aic := parseAIC(handshakeCert)

    // 2. Receive authorization certificate (application layer)
    authCert, err := receiveAuthorizationCert(conn)
    if err != nil {
        return fmt.Errorf("auth cert required: %w", err)
    }

    // 3. Verify authorization certificate chain (same CA)
    if err := verifyCertChain(authCert, trustedCAs); err != nil {
        return fmt.Errorf("auth cert chain: %w", err)
    }

    // 4. Verify belong-to: handshake cert and authorization cert strongly bound to same Agent (G4)
    //    Strong binding = same key pair (SPKI byte-for-byte equal, cryptographic binding)
    //            + same CA (same issuer) + same trust chain (authorization cert can be
    //              verified by the same trust root pool as handshake cert chain)
    //    agentId and other identity fields are for logging only, not for binding determination
    //    (UTF8String is not cryptographic binding, can be forged, see 08-dual-cert.md security considerations)
    if err := gw.VerifyBelongTo(handshakeCert, authCert, trustedCAs); err != nil {
        return fmt.Errorf("auth cert does not belong to handshake cert: %w", err)
    }

    // 5. Execute authorization decision
    authAIC := parseAIC(authCert)
    return enforcePolicy(authAIC)
}
```

## Benefits

| Dimension | Single Certificate | Dual Certificate |
|-----------|-------------------|-----------------|
| mTLS handshake overhead | Full certificate transmitted at once | Handshake certificate is lightweight (~2-4KB) |
| QUIC compatibility | Exceeding 16KB = handshake failure | ✅ Handshake certificate always under 16KB |
| Authorization cert update | Requires re-handshake | Application layer update, no TLS disconnection |
| Partial authorization change | Reissue everything | Only issue authorization certificate |
| Weak network adaptability | Large certificate transmission stutters | Handshake certificate is minimal, fast connection establishment |

## Security Considerations

| Risk | Mitigation |
|------|------------|
| Agent sends expired authorization certificate | Gateway verifies validity period + CRL/OCSP |
| Agent sends another person's authorization certificate | **belong-to strong binding (G4)**: Same key pair (SPKI byte-for-byte equal) + same CA + same trust root pool chain verification; agentId is for logging only, not a binding basis |
| Gateway does not receive authorization certificate | **Mandatory fail-close (G5)**: Missing authorization certificate = rejection. Only when the connection peer certificate itself is the authorization principal (agent==user self-authorization, cert SPKI == KeyHash) is peer certificate signature verification allowed; otherwise returns `user_auth: authorization certificate required but not provided`. No "optional (degraded)" configuration option provided |

> **G4 fix (2026-08-16)**: Early design "handshake cert.agentId == authorization cert.agentId
> **or** SPKI equal" was weak binding — agentId is UTF8String, not cryptographic binding; an attacker could
> use someone else's agentId to issue their own authorization certificate and pass the "same agentId" branch = identity forgery.
> Now enforced: **SPKI strong binding (same key pair) + same CA + same trust chain** (`pki-gateway-lib/belongto.go`
> `VerifyBelongTo`), agentId is for logging only. Dual certificates still issued by same CA, verification logic unchanged.

## Relationship to Single Certificate

Dual certificate is a **deployment strategy optimization**, not a redefinition of the AIC protocol:

- Both certificates use the **exact same ASN.1 structure** (`AIC` type)
- `delegationAuthorization` is a required field; both certificates MUST carry it (authorization certificate may use the same DA as the handshake certificate)
- The handshake certificate's `capabilities` must include at least one entry (AIC validation requires non-empty capabilities; specific placeholder capabilities defined by deployment per registry); `authorizationConstraints` may be empty (empty = no restrictions)
- If needed, it is entirely possible to fall back to single certificate mode (no splitting)
- Both use the same encoding, only split at the deployment level

## Summary

| Question | Answer |
|----------|--------|
| Can the QUIC 16KB limit be bypassed? | ✅ Yes, by sending the authorization certificate after the handshake |
| Does the AIC protocol need to be modified? | ❌ No, just deployment strategy adjustment |
| Is it consistent with Credential Bundle? | ✅ Fully consistent |
| Which delivery method is recommended? | Method A (Agent proactive push), lowest latency |
