# Encoding/Decoding Examples

## ParseAIC Usage

```go
cert, _ := x509.ParseCertificate(certDER)
aic, err := gw.ParseAIC(cert)
if err != nil {
    // unmarshal failure
}
if aic != nil {
    fmt.Printf("Agent: %s, Principal: %s\n", aic.AgentId, aic.Principal())
    fmt.Printf("DelegationMode: %d\n", aic.DelegationMode)
    for _, cap := range aic.Capabilities {
        fmt.Printf("  Cap: %s / %s\n", cap.SchemeId, cap.CapabilityId)
    }
}
```

## ValidateAIC

```go
aic, _ := gw.ParseAIC(cert)
if err := gw.ValidateAIC(aic); err != nil {
    return nil, fmt.Errorf("aic validation failed: %w", err)
}
```

## IntersectPermissions (Permission Intersection)

```go
intersection := aic.IntersectPermissions(principalAuth)
// intersection is the CapabilityId intersection of capabilities and grants
```

## RunAccessPipeline (Full Admission)

```go
result := gw.RunAccessPipeline(cert, gw.AdmissionConfig{
    RequireAIC:       true,
    RequireUserAuth:  true,
    DisallowRepresentative: true,
    NonceCache:       nonceCache,
    EnforceCapSizeConstraints: true,
    EnforceConstraints:      true,  // v1.6 enforce authorizationConstraints
})
if result.Decision != gw.DecisionAllow {
    return fmt.Errorf("access denied: %s", result.Reason)
}
```

## authorizationConstraints Example (v1.6)

### Issuing an AIC Certificate with Constraints

```json
{
  "agent_id": "deploy-agent-007",
  "principal_uid": "corp.com:zhangsan:dBjft...",
  "capabilities": [
    {"scheme_id": "mysql-v1", "capability_id": "SELECT:*"}
  ],
  "authorization_constraints": [
    {"scheme_id": "varwof/constraint-v1", "capability_id": "network:cidr",
     "parameters": "[\"10.0.0.0/8\", \"192.168.0.0/16\"]"},
    {"scheme_id": "varwof/constraint-v1", "capability_id": "session:max-concurrent",
     "parameters": "{\"max\": 3}"},
    {"scheme_id": "varwof/constraint-v1", "capability_id": "time:window",
     "parameters": "{\"start\": \"22:00\", \"end\": \"06:00\"}"}
  ]
}
```

### Gateway Runtime Checks

```
Constraint Type        Check Timing                Check Logic
─────────────────────  ──────────────────────────  ──────────────────────────
network:cidr            TLS handshake complete      Peer IP ∈ any CIDR
session:max-concurrent  New connection established  This agent connection count < max
time:window             Per request/packet          Current UTC time within window
```

## PrincipalUid Communication Format

```text
corp.com:zhangsan:dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  realm    identifier               keyFingerprint (base64url)
```

```go
pu := gw.PrincipalUid{
    Realm: "corp.com",
    Identifier: "zhangsan",
    KeyHash: sha256Hash,
}
fmt.Println(pu.String())
// → "corp.com:zhangsan:dBjft..."

parsed, err := gw.ParsePrincipalUid("corp.com:zhangsan:dBjft...")
```

> **Note**: The `realm:identifier:keyFingerprint` format produced by `PrincipalUid.String()` **is for human reading and log output only**. Machine parsing and comparison MUST be based on ASN.1 structure deserialization (`ParsePrincipalUid`); using the string split result for security decisions is strictly prohibited. If `realm` or `identifier` may contain colons internally, callers should use ASN.1 DER encapsulation for transport. `ParsePrincipalUid` is only used in display scenarios. Subject lookup/association (cascading revocation, audit, certificate queries) can be done via database index or `realm` / `identifier` fields; authorization binding still uses keyHash as the authoritative source.

## DelegationAuthorization Signing and Verification

See `06-delegation-auth.md`.

## Capability Matching

```go
// Exact match
aic.CheckPermission("http:GET:/api/v1/users")

// Glob match
matchCapability("http:GET:/api/v1/users", "http:GET:/api/v1/*") // true
matchCapability("http:GET:/api/v1/users/roles", "http:GET:/api/v1/**") // true
matchCapability("http:POST:/api/v1/data", "http:POST:/api/v1/**") // true
```
