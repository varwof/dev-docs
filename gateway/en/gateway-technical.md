# gateway — the three protocol binaries (Technical Reference)

**Module**: `github.com/varwof/gateway` (`go.mod:1`, Go 1.26.2 at `go.mod:3`)  
**Core dependency**: `github.com/varwof/gateway-core v0.4.5` (`go.mod:8`). The local `gateway-core` checkout is a newer source tree (v0.4.6); line references for `gateway-core` are handled in [gateway-core-technical.md](gateway-core-technical.md).

Three binaries share one codebase:
- `gateway-http` (L7 reverse proxy, `http/` + `cmd/http/`)
- `gateway-tcp` (L4 mapping/tunnel, `tcp/` + `cmd/tcp/`)
- `gateway-udp` (L3 forwarding, `udp/` + `cmd/udp/`)

Every layer's admission funnels through `gw.RunAccessPipeline` from gateway-core. Citations are `file.go:line`.

---

## 1. Shared bootstrap (`cmd/*` → `*cli.go`)

### Mechanism
Each binary: parse CLI/flags → build config (KV inline or file) → build shared TSA client + audit logger + TSA-proof logger → optional short-lived cert auto-issue → construct gateway → start → short-lived renewal goroutine → signal loop (SIGHUP reload, SIGINT/SIGTERM shutdown).

### Implementation
- HTTP: `main` dispatch — `cmd/http/main.go:36`; `runServer` — `cmd/http/main.go:104`; short-lived renewal loop — `cmd/http/main.go:294`; TSA client (multiple `tsa_url` → warn + use first) — `cmd/http/main.go:194-219`; shared audit logger from first listener's `audit_file` — `cmd/http/main.go:221-250`.
- TCP: `RunCLI` — `tcp/cli.go:35`; `runServer` — `tcp/cli.go:123`; `startGateway` — `tcp/cli.go:220` (renewal goroutine `tcp/cli.go:298-341`, signal loop `343-357`).
- UDP: `RunCLI` — `udp/cli.go:83` (auto-issue `222-246`, renewal `257-300`, signals `302-318`).

### Defects / risk notes
- **W35 (shared-file selection):** only the *first* listener's `tsa_url`/`audit_file` is honored; later ones are silently ignored with a warning (HTTP `main.go:211-218,244-249`).
- Short-lived renewal writes the **cert** file with mode `0644` and only the **key** with `0600` (HTTP `main.go:326-327`). Public cert is world-readable (normal), key protected.
- `http/cli.go` is a **stale duplicate** of `cmd/http/main.go`: it declares another `main()` (`cli.go:35`), `usage()` (`53`), `runServer()` (`103`) inside package `httpgw`. It compiles as dead code but is a hygiene/maintenance hazard and can diverge from the real entry point.

---

## 2. HTTP gateway (`http/`, `cmd/http/`)

### 2.1 ProxyListener — `http/proxy.go`
- `Route` — `proxy.go:53-63`; `ProxyListener` — `proxy.go:71-121` (all conn-accounting, cert/revoker/risk/policy state); `NewProxyListener` — `proxy.go:124-215` (shared transport defaults `141-156`, JWT verifier + replay nonce store `161-177`, route reverse-proxy wiring with `X-Forwarded-For` rewrite W37 `180-212`).
- `Start` — `proxy.go:218-309`: mode via `effectiveMode` (`234`); TLS/mTLS config (`235-256`); ALPN `["h2","http/1.1"]` + LRU session cache + dynamic `GetCertificate` + OCSP stapling (`258-264`); mux `/_timestamp`,`/` (`267-269`); timeouts (`271-284`); `ConnContext`/`ConnState` tracking (`286-295`).
- Connection tracking: `trackConn` — `proxy.go:315`; `trackConnState` — `proxy.go:321` (per-IP `connIPs`, `ConnectionsAccepted`, `connTotal`).
- `handleTimestamp` — `proxy.go:399` (GET-only time sync).
- `handleRequest` — `proxy.go:414-870` (main data plane):
  - strips forged trusted-identity headers W19 (`424-430`)
  - per-IP `MaxConnsPerIP` vs live `connIPs` W21 → 429 (`465-469`); `MaxTotalConns` vs `connTotal` → 503 (`471-484`)
  - JWT bearer fallback with plaintext denial (Finding 6, `497-545`)
  - capability prefix derivation (`549-569`, `deriveRequiredCaps` `944-971`)
  - **unified pipeline** `gw.RunAccessPipeline` — `proxy.go:580-603`; denial audit + 403 (`604-610`)
  - identity header injection (`619-646`); per-cert `MaxConnsPerCert` (`649-664`); revoker lifecycle (`665-673`); conn registry (`677-682`); task lifecycle/conditional revoke (`687-712`)
  - route match / 404 (`715-729`); `AllowMethods` (`731-744`); `AllowRoles` fail-closed (`746-775`); per-request expiry G2(a) (`778-787`); `X-Forwarded-Client-*` (`789-800`); `X-AIC-*` (`802-819`); WS delegation (`822-825`); completed audit + route-pattern metrics L3 (`837-869`).
- `transportForProtocol` — `proxy.go:907-937`: h2c backend → `http2.Transport{AllowHTTP:true}` (`909-916`); h1 → clone with `ForceAttemptHTTP2=false` (`917-926`); default h2-over-TLS (`927-936`); `upstreamTLSConfig` W18 (`875-905`). **Fail-closed** on upstream TLS config error — installs `upstreamTLSFailTransport` that rejects all requests loudly (fixed 2026-09-03).
- `matchRoute` — `proxy.go:973-1020`: `path.Clean` + lowercase + trailing-slash normalization + `/*` wildcard with path-separator boundary; longest-prefix wins.
- `statusResponseWriter` — `proxy.go:1022`; `wsHijackRecorder` W30 — `proxy.go:1139`; `getCert`/`UpdateCert` — `proxy.go:1167/1179`; setters — `proxy.go:1191-1253`.

### 2.2 Config — `http/config.go`
- `ListenerConfig` — `config.go:99`; `effectiveMode` (TLS-mode per protocol) — `config.go:121-144` (h3/quic always TLS1.3; others only when TLS block sets a mode); `RouteConfig` — `config.go:157`; `UpstreamTLSConfig` — `config.go:181`.
- Load/save/validate: `SetDefaults` — `213`; `LoadConfig` with `DisallowUnknownFields` W41 — `220`; `Save` (0600) — `241`; `validate` — `253` (mTLS requires CA `274`; h3/quic require cert+CA `289-297`; management requires TLS `311-318`).
- CLI: `buildListenerFromKV` — `392`; `BuildConfigFromCLI` — `458`.

### 2.3 QUIC/H3 listener — `http/quic.go`
- `h3MaxRequestBodyBytes` 1 MiB (Finding 8) — `quic.go:30`; `h3MaxResponseBodyBytes` 1 GiB — `quic.go:35`; `QUICListener` — `quic.go:38`; `Start` — `quic.go:178-279`; TLS1.3 + mTLS `RequireAndVerifyClientCert` (`190-211`); ALPN h3 `["h3","h3-29"]` (`242`) / raw QUIC `["hq","hq-29"]` (`264`).
- `connContext` per-IP/per-total (+1/-1) — `quic.go:318`; `handleH3Request` — `quic.go:343`; body cap (`353-355`); pipeline (`406-455`); per-cert (`458-473`); identity injection (`517-539`); expiry — `541`; route/audit/metrics — `578-677`.
- `matchPath` — `quic.go:680-690`: normalized path matcher (H4 `path.Clean` + case-fold), **longest-prefix match** via `matchConfigRoute` — now consistent with HTTP `matchRoute`.
- `proxyToBackend` — `quic.go:711-780`: target parse, no redirect-following (Finding 7), response body cap 1 GiB.
- Raw QUIC tunnel: `serve` — `784`; `handleConnection` (full pipeline + limits) — `798`; `handleStream` — `930`.

### 2.4 Gateway lifecycle / management / reload — `http/gateway.go`
- `NewGateway` — `gateway.go:60`; `Start` — `gateway.go:259` (CRL cache `264-272`); `Reload` — `gateway.go:417-628`:
  - two-phase atomic reload W26 (phase1 construct `481-559`, phase2 teardown `561-588`)
  - retained-listener CRL cache rebind W16 (`492-521`); `ConnExpiryRegistry` restart W04 (`566-570`); crlCaches snapshot rebuild W33 (`591-614`)
  - config persist if CLI mode (`623-625`), hot-reload risk/plugins/roles/cap reg (`432-470`)
- `loadCapabilityRegistry` — `gateway.go:226`; `startManagement` — `gateway.go:636`; handlers (`760-894`); `buildOCSPCache` W28 (default deny) — `gateway.go:896`.

### 2.5 Management API & auth
- HTTP-specific admin endpoints (`RoleAdmin`): `GET/POST /api/v1/gateway/listeners` (`665-674`), `DELETE .../{name}` (`675`), `POST /reload` (`682`), disconnect-agent/user (`693`), task lifecycle `PUT/DELETE .../tasks/{id}` + `POST .../complete` conditional revoke (`702-747`).
- Core `ManagementServer` **refuses to start** without mTLS `RequireAndVerifyClientCert` (Finding 12) and gates routes by role (`withRoles`).

### 2.6 Capability registry — `capreg/capreg.go`
- `Loader` — `capreg.go:28`; `New` — `34`; `SetTrustRoot` (PEM PKCS#7) — `44`; `Reload` (non-empty dir required, keeps-existing on failure) — `66`; `ValidateCapability` — `90`; `verifySchemeSignatures` (fail-closed on unsigned/tampered) — `101-118`.
- Injected into core package-level registry via `gw.SetGlobalCapabilityRegistry` (`gateway.go:254`), opt-in when `CapabilitySchemes` set (`gateway.go:227`); on reload with `CapabilitySchemes` unset, the global registry is cleared to `nil` (fixed 2026-09-03).

### HTTP defects / risk notes
- **FIXED (2026-09-03): two routing matchers unified.** QUIC's `matchPath` (`quic.go:680`) was rewritten to mirror the HTTP proxy's hardened matcher (H4 `path.Clean` + case-fold), and both QUIC call sites now use `matchConfigRoute` longest-match, consistent with HTTP `matchRoute`. Previously the two planes classified the same path differently (consistency/parameter-matching / RBAC-bypass risk).
- `UpstreamTLS.InsecureSkipVerify` is an explicit, documented knob (`config.go:190-192` → `proxy.go:881`), not default-on.
- **FIXED (2026-09-03): fail-closed upstream TLS.** `transportForProtocol` (`proxy.go`) no longer fails open to system roots on upstream TLS config error — a broken `UpstreamTLS` block now installs `upstreamTLSFailTransport` (rejects all requests loudly), and the same fail-closed path was applied to QUIC's `proxyToBackend` (`quic.go`).
- H3 body cap 1 MiB (`quic.go:30`) only; HTTP/1.1/2 relies on server timeouts (`proxy.go:271-284`) and has no `MaxBytesReader`.
- Bearer JWT nonce replay store `NewReplayNonceStore(0,0)` (`proxy.go:173`) is in-memory — replay protection is within-process only, cleared on restart.
- **FIXED (2026-09-03): Reload bind preflight.** `Reload` is two-phase, but a `Start()` failure after old listeners stopped could leave a partial set with no rollback. A `preflightListen` bind check now runs in Phase-1 construction (`gateway.go`) so port conflicts surface before any teardown — Reload fails cleanly with old listeners still running.
- Fallback CA for policy/cap verification is taken from the *first* listener with a CA (`gateway.go:170-175`) — wrong when listeners use different CAs.
- Admin `/reload` persists config back to the loaded path (`gateway.go:623-625`) — an admin write to a file the process may not own.
- `configsEqual` uses JSON-marshalled equality (`gateway.go:630`) — field-order/format sensitive.

---

## 3. TCP gateway (`tcp/`, `cmd/tcp/`)

### 3.1 Gateway lifecycle — `tcp/gateway.go`
- `Gateway` — `gateway.go:29`; `NewGateway` — `65` (audit chain size 1000 `81`, nonce cache/conn-expiry `87-88`, plugin registry `107-114`, policy manager `115`, risk monitor `117-124`).
- `Start` — `gateway.go:282` (CRL/OCSP caches `287-304`, mappings `306`, tunnels `335`, mgmt `347`, mesh `355`); `Stop` — `372`; `Reload` — `800` (lifecycle teardown `864`, ConnExpiry restart `873`).
- `handleRiskAction` — `228` (disconnect + conditional forced revoke G2(c) `267`).
- `startManagement` — `413` (`/api/v1/gateway/*` CRUD `442-488`); renewal endpoint **security binding** Finding 11 (`handleRenew` `676-786`: `serial_hex` and `new_pub_key_pem` must match the presented mTLS cert, `698-701`).
- `handleAddMapping` runs full `validate()` W14 (`544-617`).

### 3.2 Mapping / accept loop — `tcp/mapping.go`
- Limits: `certExpiryCheckInterval=5s` W38 (`37`); `maxMeshConns=1024` (Finding 9, `116`); `maxTunnelConns=1024` (`121`); `defaultHandshakeTimeout=30s` anti-slowloris (Finding 4, `127`).
- `idleConn` W05 (`81`); `enableTCPKeepAlive` W10 (`97-101`); `NewMapping` (`163`); `Start` (`197`); `acceptLoop` (`313`: per-IP `353-358`, total `359-364`, WaitGroup+stopCh W03 `376-385`).
- `handleConn` — `tcp/mapping.go:393-658`:
  - handshake deadline anti-DoS H5 (`457-466`)
  - **unified pipeline** `gw.RunAccessPipeline` — `479-502` (CRL→OCSP→RBAC→AIC/GS→plugins→nonce→constraints)
  - per-cert `certTracker.Add` (`509`); disconnect-on-expiry opt-in H1 (`516-531`); conn registry (`532`); cert expiry monitor G2(a) (`536-563`); periodic constraint recheck G3 (`565-590`)
  - `idleConn` wrap after TLS assertions W39 (`596-598`); half-close W06 (`631-645`).
- `handleMesh` — `665` (idle timeout W05 `706`, half-close W06 `719`).

### 3.3 Config — `tcp/config.go`
- `MappingConfig` — `117`; `effectiveMode` — `141`; limits accessors (`185-206`); idle/CRL/OCSP delegation (`225-240`); mesh **requires mTLS** W01 (`523-535`) — prevents plaintext SSRF fallback; `Save` via `os.CreateTemp` symlink-race guard (Finding 14, `89-114`, 0600).
- `TunnelConfig` — `404`; `LoadConfig` with `DisallowUnknownFields` W41 (`431-450`).

### 3.4 Tunnel client — `tcp/tunnel.go`
- `tunnelDialTimeout=10s` W08 (`23`); `NewTunnel` mTLS client via `gw.ClientTLSConfig` (`50-66`); `acceptLoop` with backoff W12 (`126`), cap `maxTunnelConns` (`151`), WaitGroup+stopCh W03 (`161-170`); dial with retry (`224`), **`crypto/rand` jitter** Finding 12 (`248-282`), `tls.DialWithDialer` 10s timeout W08 (`229-233`).

### 3.5 Mesh — `tcp/mesh.go`
- Anti-SSRF: `isLinkLocalOrMetadata` (`27`); `meshTargetMatcher` **fails closed when unconfigured** (Finding 5, `217`); `maxMeshTargetLen=4096` W38 (`38-39`); inbound allowlist validation W02 (`133-169`); **DNS-rebinding prevention** H8 (resolve + validate all IPs, `303-367`); listener hard-errors on missing mTLS W01 (`393-398`); cap 1024 (`436`).

### TCP defects / risk notes
- Per-IP limit is `map[string]int64` under a mutex — single-goroutine bottleneck under many distinct IPs (mitigated by atomic total counter W15 `351`).
- Health check (`746-793`) covers TCP mappings only; UDP/DTLS/QUIC have no backend health check.
- `configsEqual` is JSON-serialization comparison (`1037-1047`) — allocates per compare.

---

## 4. UDP gateway (`udp/`, `cmd/udp/`)

### 4.1 UDP/DTLS proxy — `udp/proxy.go`
- `maxConcurrentPackets=1024` (Finding 3, `72-74`, semaphore `95`); `UDPProxy` — `22`; `NewUDPProxy` — `77`.
- `Start` — `128` (plain UDP `140`; DTLS `187`); DTLS `RequireAndVerifyClientCert` G1 (`175-179`).
- `serve` — `270` (bounded concurrency `301-306`); `responseAmplified` reflection guard (Finding 1, `317-335`); `maxRateLimitEntries=65536` (Finding 2, `342-344`); `plaintextDefaultPktsPerIP=64` (`348-349`); `trackClient` fail-closed when bucket map full (`351-389`, evict `370-372`, fail-closed `377-379`); `evictExpiredRateBucketsLocked` (`403`); total packet rolling 60s window M2 (`411-481`, CAS `452-481`).
- `handlePacket` plaintext **fails closed** in authenticated modes (Finding 13, `493`); source-IP hash routing (H5, `510`, `selectTarget` `828-848`).
- `serveDTLS` — `560`; `handleDTLSConn` — `575-798`: pipeline `gw.RunAccessPipeline` `610`; delegated-agent `644`; per-cert `652-659`; revoker `661-668`; cert expiry `670-693`; conn registry `696-712`.

### 4.2 QUIC proxy — `udp/quic.go`
- `TLS1.3 mandatory` + ALPN `["h3","hq"]` (`125-126`); optional mTLS `RequireAndVerifyClientCert` (`135`); window sizes (`158-161`); `handleConnection` — `220` (pipeline `250-275`, limits `316-350`, token-bucket byte rate limit `363-377`, expiry `379-404`, streams `418-425`); `rateLimitedWriter` — `428`; `handleStream` — `439`; `selectTarget` round-robin M4 (`506-522`).

### 4.3 Config — `udp/config.go`
- Protocol consts — `18-28`; `ListenerConfig` — `94`; `effectiveMode` (`116-140`: QUIC defaults mtls `127`, DTLS server `132`, UDP none `137`); rate limits (`192-261`); `LoadConfig` W41 (`397-422`); `validate` (QUIC requires CA/mTLS mandatory `648`).

### UDP defects / risk notes
- Plaintext `handlePacket` is single-packet request-response only; no connection multiplexing.
- QUIC stream handler does a single-packet backend exchange per stream (no multi-message session).
- DTLS/QUIC connection-heavy paths rely on core `RunAccessPipeline`; correctness depends on caches being injected (they are, in `Gateway.Start`/`Reload`).

---

## 5. Capability registry (shared `capreg/`)

All three binaries load capabilities through `capreg` (`capreg/capreg.go`) and inject the loader into gateway-core's package-level registry. Fail-closed behavior: empty directory rejected (`67-68`), unsigned/tampered PKCS#7 trees rejected wholesale (`101-118`), failed reload keeps the existing registry (`66-81`). Verification uses `register.VerifyCapabilityPKCS7` (`109`). Tests cover trust-root verification, override, empty-dir rejection, and reload-keeps-on-error (`capreg/capreg_test.go:37-169`).

---

## 6. Unified admission call sites (all three)

| Path | Call site | Protocol |
|------|-----------|----------|
| HTTP TLS/mTLS | `http/proxy.go:580` | HTTP/1.1, HTTP/2, H2C, gRPC, WS |
| HTTP H3 | `http/quic.go:424` | HTTP/3 |
| HTTP raw QUIC | `http/quic.go:819` | QUIC tunnel |
| TCP mTLS | `tcp/mapping.go:479` | TCP |
| DTLS | `udp/proxy.go:610` | DTLS |
| QUIC | `udp/quic.go:252` | QUIC |

Shared `PipelineConfig` shape (from `tcp/mapping.go:479-502`): `CRLCache`, `OCSPCache`, `AllowRoles`, `CheckScope=CheckFullChain`, `RequireAIC`, `RequireSPIFFE`, `AllowedSPIFFEIDs`, `SPIFFETrustDomain`, `DisallowRepresentative`, `RequireUserAuth`, `RequiredCapabilities`, `CapabilityPluginRegistry/Resolver`, `PolicyVersion`, `EnforceConstraints=true`, `StrictConstraints=true`, `NonceCache`, `RiskMonitor`, `OfflineMaxCertLifetime`.

---

## 7. Cross-binary security-sensitive behaviors

- **Fail-closed** defaults wherever security is on the line: role checks on non-mTLS (`proxy.go:750`), plaintext UDP in auth modes (`udp/proxy.go:493`), mesh allowlist unconfigured (`tcp/mesh.go:217`), capability tree unsigned (`capreg.go:109`), hidden mux/QUIC paths (subscription to gateway-core mandatory).
- **`InsecureSkipVerify`** knobs exist and are documented as test/self-signed only (`gateway` `http/config.go:190-192`).
- **Management API** is hard mTLS (`RoleAdmin`/`RoleOps`) across all three.
- There are **no literal `TODO`/`FIXME`/`HACK` markers** in production source; the codebase uses a systematic `W##`, `Finding ##`, `G##`, `H##`, `M##`, `P2-A-##` comment convention tying fixes to audit findings.
