import os

DIRNAME = os.path.dirname(os.path.realpath(__file__))
# For our jwks endpoint and signing


ISSUER_URL = os.environ.get(
    "ISSUER_URL", "https://mtls.perseus-demo-authentication.ib1.org"
)  # This server, used to generate openid-configuration

UNPROTECTED_URL = os.environ.get(  # For endpoints that don't require mtls
    "UNPROTECTED_URL", "https://perseus-demo-authentication.ib1.org"
)  # This server, used to generate openid-configuration

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
    "CALLBACK_URL", f"{UNPROTECTED_URL}/api/v1/callback"
)
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
API_DOMAIN = os.environ.get("API_DOMAIN", "perseus-demo-authentication.ib1.org")


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
# Canonical Registry License URL for the energy-consumption data this EDP shares;
# published as the OAuth scope (see the IB1 OAuth profile).
ENERGY_DATA_LICENSE_URL = (
    f"{SCHEME_BASE_URL}/license/energy-consumption-edp-cap/2026-03-12"
)

DYNAMODB_TABLE = os.environ.get(
    "DYNAMODB_TABLE", "permissions-local"
)  # DynamoDB table name

MTLS_CLIENT_KEY = os.environ.get("MTLS_CLIENT_KEY")
MTLS_CLIENT_BUNDLE = os.environ.get("MTLS_CLIENT_BUNDLE")
