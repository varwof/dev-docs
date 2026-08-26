# Capability Specification

> Version: v1.0
> Status: Core specification
> Related: `01-asn1.md` (ASN.1 structure definition)

Capability is the **protocolized permission container** in the Varwof PKI system. The Core only defines the structure and matching rules; it does not define any specific capability semantics. Capability schemes are identified by `schemeId`, and the gateway routes to the corresponding plugin for decision execution by `schemeId`.

## String Representation Format

### Full Format (canonical)

```
{schemeId}:{capabilityId}
```

Examples:
- `varwof-gateway-v1:http:GET:/api/v1/users`
- `mysql:SELECT:*`
- `aws-bedrock-v2:invoke-model`

### Shorthand Format

When `schemeId` can be inferred, it may be omitted:
- `http:GET:/api/v1/users` (implies `varwof-gateway-v1` or a context default scheme)
- `SELECT:*` (implies a default database scheme)

## Parameters Encoding

Parameters are embedded in ASN.1 OCTET STRING in JSON format:

```json
{
  "max_rows": 1000,
  "timeout_ms": 5000,
  "rate_limit": {"rps": 100, "burst": 50},
  "denied_columns": ["password_hash", "ssn"]
}
```

### JSON Schema Constraints

- Top level must be a JSON object (`{}`) or array (`[]`)
- Array element types: `string`, `number`, `boolean`, `object`, `null`
- Key names: `^[a-zA-Z_][a-zA-Z0-9_]*$`
- Value types: `string`, `number`, `boolean`, `array`, `object`, `null`
- Nesting depth: maximum 8 levels
- Total size ≤ 4096 bytes (after UTF-8 encoding)

### Standard Fields (Recommended)

| Field | Type | Description |
|-------|------|-------------|
| `max_rows` | integer | Maximum return rows |
| `timeout_ms` | integer | Timeout (milliseconds) |
| `rate_limit` | object | Rate limit `{"rps":100,"burst":50}` |
| `denied_columns` | array | Columns denied access |
| `allowed_columns` | array | Columns allowed access |
| `cache_ttl` | integer | Cache TTL (seconds) |
| `require_approval` | boolean | Whether approval is required |
| `audit_level` | string | Audit level (`full` / `summary`) |

## Glob Matching Rules

### Wildcard Definitions

| Wildcard | Meaning | Match Scope | Example |
|----------|---------|-------------|---------|
| `*` | Matches one path segment | Any character except `/` | `http:GET:/api/v1/*` → `GET /api/v1/users` |
| `**` | Matches across path arbitrary depth | Includes `/` | `http:GET:/api/v1/**` → `GET /api/v1/users/roles` |
| `{a,b}` | Alternation match (**FUTURE, not implemented**) | `a` or `b` | `http:{GET,POST}:/api/*` |
| `[a-z]` | Character class match | Characters in range | `http:[A-Z]*:/api/*` |

### Detailed Rules

1. **`*` matches one path segment** (excluding `/`)
   - `http:GET:/api/v1/*` matches `GET /api/v1/users`
   - Does not match `GET /api/v1/users/roles`

2. **`**` matches across path arbitrary depth**
   - `http:GET:/api/v1/**` matches `GET /api/v1/users`, `GET /api/v1/users/roles`
   - `http:**` matches any capability under this scheme

3. **`*` can match an empty string**
   - `http:GET:/api/*/v1` matches `GET /api//v1`

4. **`{a,b}` alternation match**
   - `http:{GET,POST}:/api/*` matches `GET` or `POST`

5. **`[a-z]` character class match**
   - `http:[a-z]*:/api/*` matches lowercase methods

### Matching Priority

When multiple rules match, **the most specific rule takes precedence**:

1. Exact match: `http:GET:/api/v1/users`
2. Single-segment wildcard (`*`): `http:GET:/api/v1/*`
3. Multi-segment wildcard (`**`): `http:GET:/api/v1/**`
4. Alternation wildcard (`{a,b}`): `http:{GET,POST}:/api/*`
5. Character class wildcard (`[a-z]`): `http:[a-z]*:/api/*`
6. Scheme-level wildcard (`*`): `http:*:*`

## Built-in Capability Scheme Definitions

### `varwof-gateway-v1` — Gateway Capabilities

```
http:GET|POST|PUT|DELETE   HTTP methods
tcp:tunnel|stream          TCP modes
udp:plain|dtls|quic        UDP modes
admin:metrics|audit|policy  Management capabilities
```

### `mysql-v1` — Database Capabilities

```
SELECT  Query
INSERT  Insert
UPDATE  Update
DELETE  Delete
```

### `varwof/constraint-v1` — Authorization Boundary Constraints (v1.6, unified per 03-validation)

```
network:cidr            Allowed IP ranges
session:max-concurrent  Maximum concurrent Agent instances
time:window             Allowed execution time window
geo-fence               Geofencing (IP→region)
```

Constraints are **boundary conditions** granted by the authorizer (principal), not runtime policies:
- Determined by the authorizer, varies per individual, infrequent changes
- Verified offline by the gateway during the TLS handshake phase
- Not included as typical examples: timeout duration, retry count, rate limit threshold, backend routing, log level

See `01-asn1.md` §authorizationConstraints and `03-validation.md` §authorizationConstraints validation.

### Constraint Type Registration Mechanism

`authorizationConstraints` reuses the Capability container (`schemeId` MUST be `"varwof/constraint-v1"`, other values rejected; backward compatible with old values `"constraint"`/`"constraint-v1"`); new constraint types require registration:

```
Constraint type registration entry:
{
  "capabilityId": "device-binding",
  "parameters": {
    "type": "object",
    "properties": {
      "deviceId": { "type": "string", "maxLength": 64 },
      "tpmHash":  { "type": "string", "maxLength": 64 }
    },
    "required": ["deviceId"]
  },
  "description": "Bind to a specific device, only allow connections from that device",
  "gateway_plugin": "constraint-device-binding"
}
```

Registration fields:

| Field | Description |
|-------|-------------|
| `capabilityId` | Constraint identifier, globally unique |
| `parameters` | JSON Schema defining parameter format |
| `description` | Semantic description of the constraint |
| `gateway_plugin` | Gateway plugin name, responsible for runtime checks |

Constraint types are registered in the `Capability Scheme Registry` (`dev-docs/aic/` or `dev-docs/gateway/`). The gateway loads the corresponding constraint plugin at deployment time. Unregistered constraint types are **ignored** by the gateway by default (audit warning logged, does not block business, ensures forward compatibility); strict mode is enabled by `StrictConstraints: true` configuration.

### Plugin Deployment Model

Plugins are defined by the **`capability_plugins` JSON field** in gateway configuration (not .so/external processes); four built-in types:

| Plugin Type | Description | Configuration Method |
|------------|-------------|---------------------|
| `allowlist` | Whitelist matching, reject schemeIds not in the list | JSON array |
| `denylist` | Blacklist matching, reject schemeIds in the list | JSON array |
| `rbac` | Role-based permission check from certificate OU | JSON role→capability mapping |
| `webhook` | HTTP callback, delegate decision to external service | JSON URL + timeout |

See `dev-docs/gateway/arch/gateway-architecture.md` §Capability Plugin Engine and `gateway-core/pluginconfig.go`.

## Security Considerations

- **Length limits**: `schemeId` ≤ 128 bytes, `capabilityId` ≤ 256 bytes, `parameters` ≤ 4096 bytes
- **DoS protection**: Capability entries per AIC ≤ 256
- **Glob complexity**: `**` matching is O(n), where n is the number of target path segments
- **Fail-Closed (constraint layer)**: Unknown constraint types (under `constraint` scheme) default to audit warning + ignore; `StrictConstraints: true` enables rejection; unknown schemeId business capabilities skip plugin checks by default (audit skip), no blocking
- **Parameter validation**: JSON format, key names, nesting depth, total size

## Backward Compatibility

- No `parameters` field → behavior completely unchanged
- Old format `capabilityId` exact matching continues to be supported
- New `[a-z]` syntax is an optional feature; `{a,b}` alternation matching is FUTURE (not yet implemented)
