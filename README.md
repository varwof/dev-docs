# Varwof Developer Documentation

Developer documentation for the Varwof zero-trust PKI and AI agent
identity (AIC) stack.

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
