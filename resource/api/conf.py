import os

ENV = os.environ.get("ENV", "dev")
DIRNAME = os.path.dirname(os.path.realpath(__file__))
ISSUER_URL = os.environ.get("ISSUER_URL", "")
AUTHENTICATION_SERVER = os.environ.get(
    "AUTHENTICATION_SERVER", "https://localhost:8080"
)
OPEN_API_ROOT = "/dev" if ENV == "prod" else ""
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Can be local or s3 + ssm
SIGNING_KEY = os.environ.get("SIGNING_KEY", "/certs/edp-demo-signing-key.pem")
SIGNING_ROOT_CA_CERTIFICATE = os.environ.get(
    "SIGNING_ROOT_CA_CERTIFICATE", f"{ROOT_DIR}/certs/signing-ca-cert.pem"
)
SIGNING_BUNDLE = os.environ.get(
    "SIGNING_BUNDLE", "/certs/signing-issued-intermediate-bundle.pem"
)
API_DOMAIN = os.environ.get("API_DOMAIN", "perseus-demo-authentication.ib1.org")
PROVIDER_ROLE = os.environ.get(
    "PROVIDER_ROLE",
    "https://registry.core.pilot.trust.ib1.org/scheme/perseus/role/carbon-accounting-provider",
)
