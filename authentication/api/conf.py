import os

DIRNAME = os.path.dirname(os.path.realpath(__file__))
# For our jwks endpoint and signing


ISSUER_URL = os.environ.get("ISSUER_URL", "https://perseus-demo-authentication.ib1.org")

OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET")
OAUTH_URL = os.environ.get("OAUTH_URL")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
AUTHORIZATION_ENDPOINT = os.environ.get(
    "AUTHORIZATION_ENDPOINT",
    f"{OAUTH_URL}/oauth2/auth",
)
TOKEN_ENDPOINT = os.environ.get(
    "TOKEN_ENDPOINT",
    f"{OAUTH_URL}/oauth2/token",
)
REDIRECT_URI = os.environ.get(
    "REDIRECT_URI", "https://perseus-demo-accounting.ib1.org/callback"
)
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
API_DOMAIN = os.environ.get("API_DOMAIN", "perseus-demo-authentication.ib1.org")
ENV = os.environ.get("ENV", "dev")

JWT_SIGNING_KEY = os.environ.get(
    "JWT_SIGNING_KEY", f"/copilot/perseus-directory/{ENV}/secrets/jwt-signing-key"
)
