"""OpenAPI customisation for the IB1 Trust Framework OAuth profile.

FastAPI enforces auth via plain dependencies (``parsed_client_cert``) and a raw
``Header`` parameter rather than ``Security(...)`` classes, so none of the auth
machinery is inferred into the generated schema. We inject it here.

OpenAPI 3.1 (emitted by this FastAPI version) can express the mTLS client
certificate (``mutualTLS``) and the OAuth2 authorization-code flow natively.
Other parts of the IB1 OAuth profile have no native representation and are
documented narratively in the descriptions below:

- Pushed Authorization Requests (RFC 9126) — no flow field exists for the PAR
  endpoint; the client must POST to ``/api/v1/par`` before authorizing.
- Token-to-certificate binding — the token's ``client_id`` must equal the
  Application Directory URL in the client certificate (no OpenAPI field models
  this relationship).
- PKCE S256 (RFC 7636).

Note: mTLS terminates at the load balancer and is forwarded to the app as the
``x-amzn-mtls-clientcert-leaf`` header, so Swagger UI "Try it out" cannot perform
the real flow — these docs are for human comprehension and code generation.
"""

from . import conf

# IB1 Trust Framework specifications.
CERTIFICATE_SPEC = (
    "https://specification.trust.ib1.org/member-identity-digital-certificates/1.0/"
)
OAUTH_SPEC = (
    "https://specification.trust.ib1.org/"
    "oauth-with-member-identity-certificates/1.0/#oauth-profile"
)

# Per the OAuth profile, each scope is a Registry License URL. Both derive from
# conf.SCHEME_BASE_URL so the published scopes stay consistent with the deployed
# environment. A client requests one of them, not both.
OAUTH2_SCOPES: dict[str, str] = {
    conf.ENERGY_CONSUMPTION_LICENSE_URL: (
        "Energy consumption data shared from EDP to CAP"
    ),
    conf.ENERGY_CONSUMPTION_EMISSIONS_LICENSE_URL: (
        "Energy consumption data shared from EDP to CAP, where the same permission "
        "also covers the CAP sharing the resulting emissions data with the consumer's "
        "chosen FSP"
    ),
}

API_DESCRIPTION = f"""\
Perseus Demo Authentication Server — an OAuth 2.0 authorization server
implementing the IB1 Trust Framework
[OAuth with Member Identity Certificates]({OAUTH_SPEC}) profile. Clients
authenticate with [Member identity certificates]({CERTIFICATE_SPEC}).

### Authorization flow

1. **Pushed Authorization Request (PAR, RFC 9126).** The client authenticates
   with **mTLS** (`tls_client_auth`) and POSTs the authorization parameters to
   `/api/v1/par`, receiving a `request_uri`. The `scope` is a Registry License
   URL and the `client_id` is the Application's Directory URL taken from the
   certificate.
2. **Authorize.** The user-agent is sent to `/api/v1/authorize?request_uri=…`,
   which redirects to the upstream Ory Hydra authorization endpoint.
3. **Callback proxy.** Hydra redirects to `/api/v1/callback`, which forwards the
   user back to the client's original redirect URI (looked up by `state`).
4. **Token.** The client authenticates with **mTLS** and exchanges the code at
   `/api/v1/authorize/token` using **PKCE (S256)**. The issued access token is
   **bound to the certificate**: its `client_id` is the Application Directory URL
   from the certificate, and the resource server requires the two to match.

All protected endpoints require a Member client certificate issued under the IB1
Trust Framework and carrying the required Member Role (a Directory URL). See the
sequence diagram in `docs/`.

**Relevant RFCs:** 6749 (OAuth2), 9126 (PAR), 7636 (PKCE).
"""


def add_fapi_security_schemes(openapi_schema: dict) -> dict:
    """Inject the mTLS and OAuth2 security schemes into the generated schema."""
    components = openapi_schema.setdefault("components", {})
    schemes = components.setdefault("securitySchemes", {})
    schemes["mtls"] = {
        "type": "mutualTLS",
        "description": (
            "Mutual TLS using a Member client certificate issued under the IB1 "
            "Trust Framework, identifying the calling Application by its Directory "
            "URL and carrying the required Member Role. See the Member Identity "
            f"Digital Certificates specification: {CERTIFICATE_SPEC}. Presented at "
            "the TLS layer; the load balancer forwards it to the application as "
            "the `x-amzn-mtls-clientcert-leaf` header. Required by the PAR, token, "
            "permissions and revocation endpoints."
        ),
    }
    schemes["fapiOAuth2"] = {
        "type": "oauth2",
        "description": (
            "OAuth 2.0 authorization-code flow per the IB1 'OAuth with Member "
            f"Identity Certificates' profile ({OAUTH_SPEC})."
            "__nb.__ Swagger UI's authorize dialog shows `client_id` / "
            "`client_secret` fields for this flow, but the IB1 profile does NOT "
            "use a client secret — clients authenticate with mTLS "
            "(`tls_client_auth`) and PKCE. 'Try it out' cannot complete the real "
            "flow."
        ),
        "flows": {
            "authorizationCode": {
                "authorizationUrl": f"{conf.UNPROTECTED_URL}/api/v1/authorize",
                "tokenUrl": f"{conf.ISSUER_URL}/api/v1/authorize/token",
                "refreshUrl": f"{conf.ISSUER_URL}/api/v1/authorize/token",
                "scopes": OAUTH2_SCOPES,
            }
        },
    }
    return openapi_schema
