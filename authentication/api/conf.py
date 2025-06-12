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

ORY_AUTHORIZATION_ENDPOINT = (
    os.environ.get(  # User logins are handled on Ory Hydra via a 302 redirect
        "ORY_AUTHORIZATION_ENDPOINT",
        f"{ORY_URL}/oauth2/auth",
    )
)

REDIRECT_URI = os.environ.get(  #
    "REDIRECT_URI", "https://perseus-demo-accounting.ib1.org/callback"
)
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
API_DOMAIN = os.environ.get("API_DOMAIN", "perseus-demo-authentication.ib1.org")


JWT_SIGNING_KEY = os.environ.get(
    "JWT_SIGNING_KEY", f"/copilot/perseus-directory/{ENV}/secrets/jwt-signing-key"
)

PROVIDER_ROLE = os.environ.get(
    "PROVIDER_ROLE",
    "https://registry.core.pilot.trust.ib1.org/scheme/perseus/role/carbon-accounting-provider",
)

DYNAMODB_TABLE = os.environ.get(
    "DYNAMODB_TABLE", "permissions-local"
)  # DynamoDB table name
