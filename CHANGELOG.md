# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- preprod points at the sandbox Registry. The `dev` CDK context, which preprod deploys, set `SCHEME_BASE_URL` to `registry.core.development.trust.ib1.org`, a host that does not resolve, so `PROVIDER_ROLE`, `TRUST_FRAMEWORK_URL` and both license URLs were derived from a Registry that does not exist and no client's scope could match
- The Permission Record's `license` is the Registry License URL selected from the token's granted scopes, rather than whichever scope Ory Hydra happened to return first. Records previously named a license that does not resolve in the Registry, and disagreed with the provenance record for the same transaction
- Provenance transfer steps name `standard/energy-consumption-data/2026-03-12`, the `ib1:SchemeCatalogRequirements` document that also pins the license the same step records. The retired `2024-12-05` version does not resolve in the Registry, and was missed when the license moved to `energy-consumption-edp-cap/2026-03-12` in v3.0.0
- Provenance origin steps use the assurance vocabularies the Registry actually publishes. `originMethod` under `assurance/origin-method/` replaces `processing` under `assurance/processing/`, and `dataSource` is removed. Neither previous URL resolved, and the source type is already carried by `sourceType`
- A token carrying no Registry License URL among its scopes is rejected rather than storing a non-license value as the permission's license. An empty or absent `scp` previously raised `IndexError`/`KeyError`
- The Ory client setup in the README lists both Registry License URLs as the scopes rather than `profile`, and a single `Code` response type rather than `Code and ID Token`
- The energy consumption data is offered under two Registry Licenses, `energy-consumption-edp-cap/2026-03-12` and `energy-consumption-emissions-edp-cap-fsp/2026-03-12`. The Scheme Catalog Requirements carry `ib1:requireOneOrMoreOf` on `dcterms:license`, so a Data Service may be offered under either. Both are advertised as OAuth scopes, and a client requests one of them
- Provenance records name the license granted on the token rather than a fixed constant. With two valid licenses a constant could assert a license the user did not consent to, and it would have been the FSP leg, the part carrying the extra `ib1:additionalCondition`, that went missing
- **The EDP signing private key is no longer written to the logs.** `resource/api/provenance.py` logged it at INFO on every call, so it reached CloudWatch in plaintext. That whole debug block is removed, and a test now fails if it comes back. Treat any key used by a deployed build as compromised and rotate it

### Breaking

- Provenance record structure changed. Origin steps carry `perseus:assurance.originMethod` in place of `perseus:assurance.processing`, and no longer carry `perseus:assurance.dataSource`. This alters the signed record structure
- The token endpoint rejects a token whose granted scopes carry no Registry License URL under this deployment's `SCHEME_BASE_URL`. Any scope was previously accepted, and the first one was stored as the permission's `license`. A deployment whose OAuth client grants only `profile` and `offline_access`, or only a license from a different Registry environment, must have its client registration updated before this release
- The Permission Record's `license` changes value for existing integrations, from whichever scope was granted first to the Registry License URL. Anything matching on the old value needs updating
- `create_provenance_records` takes a required `license_url` argument. Any caller outside this repository needs updating

## [v4.0.0] - 2026-08-26

### Breaking

- Error responses changed shape. Both APIs now answer with `{"error": ..., "error_description": ...}` where they previously answered `{"detail": "..."}`. Anything reading `detail` needs updating
- Request validation failures return `400` with that shape, not `422` with Pydantic's `loc`/`msg`/`type` list
- `/datasources/{id}/{measure}` rejects a measure outside `availableMeasures` with `400`. Any value was previously accepted

### Changed

- The PAR, token, revocation and permissions endpoints return errors in the RFC 6749 section 5.2 shape, `{"error": ..., "error_description": ...}`, instead of FastAPI's `{"detail": "..."}`. Ory Hydra's non-standard `error_hint` is included where it is forwarded
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
- Removed the unused S3, SSM and CloudWatch Logs VPC endpoints from the resource VPC: the Lambda runs outside the VPC, so nothing could route through them and the two interface endpoints billed ~$16/month per environment

### Fixed

- The evidence page returns `404` for an unknown evidence ID, instead of `200` with a "Not found" body
- Removed `resource/cdk/lambda_code/lambda_authorizer.py`. It was a leftover from an API Gateway deployment since replaced by an ALB, was referenced nowhere, and described an authentication path that does not exist
- An unreachable Ory Hydra returns `502`, and a timeout `504`, instead of an unhandled `500`
- An unreachable JWKS endpoint, or a key ID that has been rotated away, returns `502` instead of an unhandled `500` in the authentication app
- The token endpoint no longer logs the access token, the refresh token or the full token claims. A short reference is logged instead so a request can still be traced
- Unhandled failures return `server_error` with a `correlation_id` that also appears in the log line carrying the traceback, instead of a bare `500 Internal Server Error` with no body. Redis, DynamoDB and SSM failures were all unreportable
- A bearer token that is not a JWT, or whose header carries no key id, returns `401` instead of `500`. Reading the token header sat outside the try in both apps
- The signing key falls back to the local file when AWS is not configured at all. The SSM client was built outside the `try`, so a missing region raised before the fallback could run
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
