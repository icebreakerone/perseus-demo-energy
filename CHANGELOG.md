# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- Certificate errors return `401` instead of `500`: the resource API caught a local exception class unrelated to the `ib1.directory` hierarchy that `require_role` raises, so a valid certificate with the wrong role returned `500`; malformed certificates and certificates missing the role or application extension are now also rejected with `401` in both apps
- An access token returned by Ory Hydra that cannot be decoded gives `502` from the token endpoint rather than an unhandled `500`

## [v3.0.0] - 2026-06-09

### Added

- OpenAPI security schemes documenting the FAPI authentication: mTLS (`mutualTLS`) and the OAuth2 authorization-code flow on the authentication server, and mTLS plus a certificate-bound bearer token on the resource server, with per-endpoint security requirements
- Citations to the IB1 Trust Framework specifications (member-identity certificates, OAuth profile, provenance records) in the API documentation
- `SCHEME_BASE_URL` as a single source of truth for registry/scheme URLs in the authentication app (previously only present in the resource app)
- Proxy callback URLs: a single registered callback URL serves all clients — each client's requested callback is stored at the PAR stage and the callback response from Ory is proxied back, avoiding per-client callback registration

### Changed

- Registry/scheme configuration is now environment-aware: `PROVIDER_ROLE`, `TRUST_FRAMEWORK_URL`, and the OAuth scope derive from `SCHEME_BASE_URL`, wired through CDK per deployment environment (dev → development, prod → sandbox — the prod demo apps run on the sandbox trust framework for testing)
- Add the Core (development) Trust Framework client CA (root + intermediate) to the dev mTLS trust store, and refresh both the authentication and resource trust stores in `renew_truststores.sh` (each snapshots the shared bundle independently)
- API docs describe token-to-certificate binding as `client_id` matching the certificate Directory URL, in line with the OAuth profile (rather than `cnf`/`x5t#S256`)
- Removed the `cnf.x5t#S256` certificate-thumbprint token binding; access tokens are now bound to the client solely via `client_id` matching the certificate Directory URL
- Removed all `x-fapi-interaction-id` handling (request parameter and response header), as `x-fapi-*` headers are not part of the IB1 OAuth profile
- Removed the non-standard `transaction` field from provenance transfer steps
- `messaging.py` derives the trust-framework URL from configuration instead of a hardcoded host

### Fixed

- Corrected provenance records to American `license` spelling, matching the machine-readable registry (previously British `licence`)
- Corrected the OAuth scope to a valid registry license URL (the previous `energy-consumption-data/2024-12-05` does not exist in the registry)
- Prod CAP role check rejected valid certificates: prod `scheme_base_url` pointed at the core registry, so the expected role (`registry.core.trust.ib1.org/.../carbon-accounting-provider`) did not match the certificates' sandbox-scoped role; corrected prod to the sandbox registry

### Breaking

- Access tokens no longer carry the `cnf.x5t#S256` claim, and the resource server no longer enforces certificate-thumbprint binding (client_id binding only)
- Protected responses no longer return the `x-fapi-interaction-id` header
- Provenance transfer steps no longer include the `transaction` field
- Provenance record field names changed: `licences` → `licenses`, `licence` → `license`, `originLicence` → `originLicense`, altering the signed-record structure
- OAuth scope / license value changed to `…/scheme/perseus/license/energy-consumption-edp-cap/2026-03-12` (from the previous `energy-consumption-data/2024-12-05` and `scheme/electricity` variants)

## [v2.0.0] - 2026-02-19

### Added

- Documentation updates detailing endpoints
- Send message to client endpoint on revocation via mTLS
- Adds detail of all endpoints to README.md
- Remove details of deprecated client.py

### Fixed

- Meter listing endpoint /datasources requires mtls and token authentication

### Changed

- Removed references to deprecated client.py script

## [v1.0.3] - 2025-12-15

### Fixed

- Remove leading dot from authorization_endpoint in prod well-known response

## [v1.0.2] - 2025-12-08

### Added

-

### Changed

- Raise a 404 for an incorrect meter ID

### Fixed

- Add missing location fields to resource api responses

### Breaking

-

## [v1.0.1] - 2025-11-27

### Added

- CHANGELOG.md

### Changed

-

### Fixed

- Incorrect date formats in provenance records
- Missing fields in well known response
- Trust framework URLs are configurable
- Fixes issue in deployment that added an @ to the root domain A record alias

### Breaking

-

## [v1.0.0] - 2025-11-27

Initial tagged release. Previous history is unversioned
