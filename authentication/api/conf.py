import os

DIRNAME = os.path.dirname(os.path.realpath(__file__))
# For our jwks endpoint and signing
CERTS = {
    "cert": os.environ.get(
        "DIRECTORY_CERTIFICATE",
        os.path.join(DIRNAME, "certs", "server-signing-public-key.pem"),
    ),
    "key": os.environ.get(
        "DIRECTORY_PRIVATE_KEY",
        os.path.join(DIRNAME, "certs", "server-signing-private-key.pem"),
    ),
}


ISSUER_URL = os.environ.get("ISSUER_URL", "https://perseus-demo-energy.ib1.org")
CLIENT_ID = os.environ.get("CLIENT_ID", "21653835348762")
CLIENT_SECRET = os.environ.get(
    "CLIENT_SECRET", "uE4NgqeIpuSV_XejQ7Ds3jsgA1yXhjR1MXJ1LbPuyls"
)
AUTHORIZATION_ENDPOINT = os.environ.get(
    "AUTHORIZATION_ENDPOINT",
    "https://musing-kirch-t48np94ikp.projects.oryapis.com/oauth2/auth",
)
TOKEN_ENDPOINT = os.environ.get(
    "TOKEN_ENDPOINT",
    "https://musing-kirch-t48np94ikp.projects.oryapis.com/oauth2/token",
)
INTROSPECTION_ENDPOINT = os.environ.get(
    "INTROSPECTION_ENDPOINT",
    "https://musing-kirch-t48np94ikp.projects.oryapis.com/admin/oauth2/introspect",
)
REDIRECT_URI = os.environ.get(
    "REDIRECT_URI", "https://perseus-demo-accounting.ib1.org/callback"
)
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
