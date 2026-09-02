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
