# Varwof Developer Documentation

Developer documentation for the Varwof zero-trust PKI and AI agent
identity (AIC) stack.

## Platform Documentation

Developer / architecture documentation for the Varwof platform components
(documentation lives here; the product / operations docs ship with each repo):

- [Varwof Core](core/README.md) — PKI infrastructure: architecture,
  PKI architecture, PKI hierarchy, RBAC model
  ([中文版](core/README_CN.md); per-document translations in
  [`core/en/`](core/en/) and [`core/zh/`](core/zh/))
- [Varwof Client](client/README.md) — CLI management client for the core CA
  API ([中文版](client/README_CN.md))
- [Varwof Gateway](gateway/README.md) — three-layer zero-trust security
  gateway for TCP/HTTP/UDP ([中文版](gateway/README_CN.md))

## AIC Specification

The AIC (Agent Identity Certificate) specification — an X.509
certificate extension binding agent identity to a responsible principal,
with structured delegation, capability and authorization-boundary
semantics:

- [AIC Identity & Authorization Specification](aic/README.md)
  (English primary; [中文版](aic/README_CN.md); per-section
  translations in [`aic/en/`](aic/en/) and [`aic/zh/`](aic/zh/))
- IETF drafts:
  [`draft-wei-aic-identity-cert-00`](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/)
  and
  [`draft-wei-aic-jwt-00`](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)
- IPR: Royalty-Free for all implementers (IETF IPR disclosures
  [7553](https://datatracker.ietf.org/ipr/7553) /
  [7565](https://datatracker.ietf.org/ipr/7565))

## Related repositories

Source code lives in the other `varwof/*` repositories (`core`,
`types`, `gateway`, `aic-jwt`, ...); see the organization
[README](https://github.com/varwof/.github).

## License

Apache-2.0 unless a specific document states otherwise.
