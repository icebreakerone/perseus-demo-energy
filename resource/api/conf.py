import os

ENV = os.environ.get("ENV", "dev")
DIRNAME = os.path.dirname(os.path.realpath(__file__))
ISSUER_URL = os.environ.get("ISSUER_URL", "")
AUTHENTICATION_SERVER = os.environ.get(
    "AUTHENTICATION_SERVER", "https://localhost:8080"
)
OPEN_API_ROOT = "/dev" if ENV == "prod" else ""
CATALOG_ENTRY_URL = "https://perseus-demo-energy.ib1.org/data-service/consumption"
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Probably should include the bundles and certificates in the image?
# Or they are retrieved from s3
SIGNING_KEY = os.environ.get("SIGNING_KEY", "/certs/edp-demo-signing-key.pem")
SIGNING_ROOT_CA_CERTIFICATE = os.environ.get(
    "SIGNING_ROOT_CA_CERTIFICATE", f"{ROOT_DIR}/certs/signing-ca-cert.pem"
)
SIGNING_BUNDLE = os.environ.get(
    "SIGNING_BUNDLE", "/certs/signing-issued-intermediate-bundle.pem"
)
AUTHENTICATION_SERVER_CA = os.environ.get(
    "AUTHENTICATION_SERVER_CA", "/certs/server-ca-cert.pem"
)

API_DOMAIN = os.environ.get("API_DOMAIN", "perseus-demo-authentication.ib1.org")
