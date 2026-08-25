# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- The PAR, token, revocation and permissions endpoints return errors in the RFC 6749 section 5.2 shape, `{"error": ..., "error_description": ...}`, instead of FastAPI's `{"detail": "..."}`. Ory Hydra's non-standard `error_hint` is included where it is forwarded. The `422` validation shape and the `/authorize` and `/callback` endpoints are unchanged for now
- Errors from Ory Hydra are parsed and mapped rather than passed through. Only `error_description` and `error_hint` are forwarded, and only for errors the caller can act on. `error_debug`, which Ory populates with internal detail, is never forwarded, and an unparseable body is dropped rather than relayed
- The status returned for an upstream failure is chosen from Hydra's `error` code rather than its HTTP status. `invalid_client` and `unauthorized_client` describe the client authenticated at Hydra, which is this service, so they now return `502` rather than telling the caller their own authentication failed
- Both calls to Ory Hydra now set a timeout, `ORY_TIMEOUT`, defaulting to 10 seconds
- One wording for each condition. A missing client certificate is `Client certificate required` in both apps, and an expired token is `Token expired` whichever check catches it. No error message ends in a full stop or an exclamation mark
- A missing local Ory credential returns `server_error` in the same shape as Hydra rejecting one, rather than `{"detail": "Client ID and Secret not set"}`. It stays a `500` against the `502` for a rejected credential, since the request never reached upstream, and the names of the unset variables go to the logs rather than to the caller
- Removed the unreachable `Failed to revoke permission` response. `revoke_permission` either returns a permission or raises
- Every error in both apps now uses one shape. The Authentication API answers `{"error": ..., "error_description": ...}` throughout, and the Resource API the same with RFC 6750 error codes. `HTTPException` is no longer raised anywhere
- The Resource API sends a `WWW-Authenticate` challenge on every `401`, which the IB1 ops guidelines ask of a Data Provider. A request carrying no bearer token gets a bare `Bearer` challenge with no error code, per RFC 6750 section 3
- Request validation failures return `400 invalid_request` naming each failing parameter and why, instead of FastAPI's `422` with Pydantic's `loc`/`msg`/`type` list
- `measure` on `/datasources/{id}/{measure}` is validated against the same list `/datasources` advertises as `availableMeasures`. Any value was previously accepted and returned the same sample data. The allowed values now appear in the OpenAPI schema

### Fixed

- The evidence page returns `404` for an unknown evidence ID, instead of `200` with a "Not found" body
- Removed `resource/cdk/lambda_code/lambda_authorizer.py`. It was a leftover from an API Gateway deployment since replaced by an ALB, was referenced nowhere, and described an authentication path that does not exist
- An unreachable Ory Hydra returns `502`, and a timeout `504`, instead of an unhandled `500`
- An unreachable JWKS endpoint, or a key ID that has been rotated away, returns `502` instead of an unhandled `500` in the authentication app
- The token endpoint no longer logs the access token, the refresh token or the full token claims. A short reference is logged instead so a request can still be traced
- Unhandled failures return `server_error` with a `correlation_id` that also appears in the log line carrying the traceback, instead of a bare `500 Internal Server Error` with no body. Redis, DynamoDB and SSM failures were all unreportable
- A bearer token that is not a JWT, or whose header carries no key id, returns `401` instead of `500`. Reading the token header sat outside the try in both apps
- Resource API log lines are interpolated. They used `%s` placeholders with loguru, which formats with `{}`, so the values were dropped and the placeholders logged literally
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
