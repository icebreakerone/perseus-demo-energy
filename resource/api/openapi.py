"""OpenAPI customisation for the resource server's IB1 Trust Framework protection.

Protected endpoints require BOTH a mutual-TLS client certificate AND a
certificate-bound bearer token. FastAPI enforces this through a plain dependency
(``require_mtls_and_token``) rather than ``Security(...)`` classes, so we inject
the security schemes here.

OpenAPI 3.1 (emitted by this FastAPI version) expresses the client certificate
as ``mutualTLS`` and the access token as an ``http``/``bearer`` JWT. The binding
between them — the token's ``client_id`` must equal the Application Directory URL
in the certificate — has no native OpenAPI representation and is documented
narratively below.

Note: mTLS terminates at the load balancer and arrives as the
``x-amzn-mtls-clientcert-leaf`` header, so Swagger UI "Try it out" cannot perform
the real flow.
"""

# IB1 Trust Framework specifications.
CERTIFICATE_SPEC = (
    "https://specification.trust.ib1.org/member-identity-digital-certificates/1.0/"
)
OAUTH_SPEC = (
    "https://specification.trust.ib1.org/"
    "oauth-with-member-identity-certificates/1.0/#oauth-profile"
)
PROVENANCE_SPEC = "https://specification.trust.ib1.org/provenance-records/1.0/"

API_DESCRIPTION = f"""\
Perseus Demo Resource API (Energy Data Provider). Demonstrates protected
endpoints secured under the IB1 Trust Framework
[OAuth with Member Identity Certificates]({OAUTH_SPEC}) profile.

Every protected endpoint requires **both**:

1. **Mutual TLS** — a [Member client certificate]({CERTIFICATE_SPEC}) issued under
   the IB1 Trust Framework, identifying the calling Application by its Directory
   URL and carrying the required Member Role; and
2. **A certificate-bound access token** obtained from the authentication server.
   The token's `client_id` MUST equal the Application Directory URL in the
   presented client certificate — the resource server rejects any mismatch,
   expired token, or invalid signature with `401`.

Meter data is returned with a signed
[provenance record]({PROVENANCE_SPEC}).
"""


# Single requirement object listing both schemes => both are required (AND).
PROTECTED_SECURITY = [{"mtls": [], "certificateBoundToken": []}]


def apply_protected_security(openapi_schema: dict) -> dict:
    """Replace the bare auto-generated bearer requirement with mTLS + token.

    FastAPI infers a ``[{"HTTPBearer": []}]`` requirement from the ``HTTPBearer``
    dependency. Every operation that carries it is in fact protected by both
    mTLS and a certificate-bound token, so we overwrite it with the combined
    (AND) requirement and drop the bare ``HTTPBearer`` scheme.
    """
    for path_item in openapi_schema.get("paths", {}).values():
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            security = operation.get("security")
            if security and any("HTTPBearer" in req for req in security):
                operation["security"] = [dict(req) for req in PROTECTED_SECURITY]
    openapi_schema.get("components", {}).get("securitySchemes", {}).pop(
        "HTTPBearer", None
    )
    return openapi_schema


def add_fapi_security_schemes(openapi_schema: dict) -> dict:
    """Inject the mTLS and certificate-bound bearer-token security schemes."""
    components = openapi_schema.setdefault("components", {})
    schemes = components.setdefault("securitySchemes", {})
    schemes["mtls"] = {
        "type": "mutualTLS",
        "description": (
            "Mutual TLS using a Member client certificate issued under the IB1 "
            "Trust Framework, identifying the calling Application by its Directory "
            "URL and carrying the required Member Role. See the Member Identity "
            f"Digital Certificates specification: {CERTIFICATE_SPEC}. Presented at "
            "the TLS layer; the load balancer forwards it as the "
            "`x-amzn-mtls-clientcert-leaf` header."
        ),
    }
    schemes["certificateBoundToken"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": (
            "Certificate-bound access token issued by the authentication server. "
            "The token is bound to the calling Application's Directory URL: its "
            "`client_id` MUST equal the URL in the presented mTLS client "
            f"certificate. See the OAuth profile: {OAUTH_SPEC}."
        ),
    }
    return openapi_schema
