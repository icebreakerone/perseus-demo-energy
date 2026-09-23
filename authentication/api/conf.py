import datetime
import os

DIRNAME = os.path.dirname(os.path.realpath(__file__))
# For our jwks endpoint and signing


# The OAuth issuer identifier (RFC 8414 section 2). The metadata document is
# published at this URL and names it as the issuer, tokens carry it as iss, and
# the Directory records it as the oauthIssuer. It is the host that does not
# require a client certificate, so a browser can reach the authorization
# endpoint and any client can read the metadata.
ISSUER_URL = os.environ.get(
    "ISSUER_URL", "https://perseus-demo-authentication.ib1.org"
)

# The host serving the server-to-server endpoints, which require mTLS. The
# issuer identifier does not have to host these (RFC 8705 section 5).
MTLS_URL = os.environ.get(
    "MTLS_URL", "https://mtls.perseus-demo-authentication.ib1.org"
)

ENV = os.environ.get("ENV", "dev")

ORY_CLIENT_SECRET = os.environ.get(
    "ORY_CLIENT_SECRET"
)  # Ory Hydra Oauth2 client secret for local dev
ORY_CLIENT_SECRET_PARAM = os.environ.get(
    "ORY_CLIENT_SECRET_PARAM"
)  # To retrieve the secret from SSM
ORY_CLIENT_ID = os.environ.get("ORY_CLIENT_ID")  # Ory Hydra Oauth2 client
ORY_URL = os.environ.get("ORY_URL")  # Ory Hydra Oauth2 server
ORY_TOKEN_ENDPOINT = os.environ.get(
    "ORY_TOKEN_ENDPOINT",
    f"{ORY_URL}/oauth2/token",
)

# Seconds to wait for Ory Hydra. Deliberately below the API Gateway integration
# timeout of 30s, so that a slow upstream produces our error rather than a
# shapeless 504 from the infrastructure.
ORY_TIMEOUT = float(os.environ.get("ORY_TIMEOUT", "10"))

ORY_AUTHORIZATION_ENDPOINT = (
    os.environ.get(  # User logins are handled on Ory Hydra via a 302 redirect
        "ORY_AUTHORIZATION_ENDPOINT",
        f"{ORY_URL}/oauth2/auth",
    )
)

REDIRECT_URI = os.environ.get(  #
    "REDIRECT_URI", "https://perseus-demo-accounting.ib1.org/callback"
)
CALLBACK_URL = os.environ.get(
    "CALLBACK_URL", f"{ISSUER_URL}/api/v1/callback"
)
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")


JWT_SIGNING_KEY = os.environ.get(
    "JWT_SIGNING_KEY", f"/copilot/perseus-directory/{ENV}/secrets/jwt-signing-key"
)

# SCHEME_BASE_URL is the single source of truth for the Perseus scheme in the Trust
# Registry, controlling which environment (sandbox/development/pilot/core) is
# referenced. Env-overridable; the sandbox default is used for local/docker/test.
SCHEME_BASE_URL = os.environ.get(
    "SCHEME_BASE_URL",
    "https://registry.core.sandbox.trust.ib1.org/scheme/perseus",
)
# Registry root = SCHEME_BASE_URL minus the trailing "/scheme/<name>".
REGISTRY_BASE_URL = SCHEME_BASE_URL.rsplit("/scheme/", 1)[0]

PROVIDER_ROLE = os.environ.get(
    "PROVIDER_ROLE",
    f"{SCHEME_BASE_URL}/role/carbon-accounting-provider",
)
TRUST_FRAMEWORK_URL = os.environ.get(
    "TRUST_FRAMEWORK_URL",
    f"{REGISTRY_BASE_URL}/trust-framework",
)
# Registry License URLs this EDP offers the energy consumption data under, published
# as the OAuth scopes (see the IB1 OAuth profile). The Scheme Catalog Requirements for
# the energy-consumption-data API carry ib1:requireOneOrMoreOf on dcterms:license, so a
# Data Service may be offered under either or both. The second also covers the onward
# transfer to the consumer's chosen FSP, taken in the same permission.
ENERGY_CONSUMPTION_LICENSE_URL = (
    f"{SCHEME_BASE_URL}/license/energy-consumption-edp-cap/2026-03-12"
)
ENERGY_CONSUMPTION_EMISSIONS_LICENSE_URL = (
    f"{SCHEME_BASE_URL}/license/energy-consumption-emissions-edp-cap-fsp/2026-03-12"
)
ENERGY_DATA_LICENSE_URLS = (
    ENERGY_CONSUMPTION_LICENSE_URL,
    ENERGY_CONSUMPTION_EMISSIONS_LICENSE_URL,
)
# How long a Permission granted under each License lasts, as the License declares
# in ib1:licenseDuration in the Registry
LICENSE_DURATIONS = {
    ENERGY_CONSUMPTION_LICENSE_URL: "1 year",
    ENERGY_CONSUMPTION_EMISSIONS_LICENSE_URL: "1 year",
}

# Must match the refresh token lifespan set in the Ory Hydra tenant. Hydra does
# not report it in the token response.
REFRESH_TOKEN_LIFESPAN = datetime.timedelta(
    hours=int(os.environ.get("REFRESH_TOKEN_LIFESPAN_HOURS", "720"))
)

DYNAMODB_TABLE = os.environ.get(
    "DYNAMODB_TABLE", "permissions-local"
)  # DynamoDB table name

MTLS_CLIENT_KEY = os.environ.get("MTLS_CLIENT_KEY")
MTLS_CLIENT_BUNDLE = os.environ.get("MTLS_CLIENT_BUNDLE")
