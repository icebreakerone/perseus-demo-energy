import os

ENV = os.environ.get("ENV", "dev")
DIRNAME = os.path.dirname(os.path.realpath(__file__))
ISSUER_URL = os.environ.get("ISSUER_URL", "")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET")
OPEN_API_ROOT = "/dev" if ENV == "prod" else ""
CATALOG_ENTRY_URL = "https://perseus-demo-energy.ib1.org/data-service/consumption"
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGNING_KEY = os.environ["SIGNING_KEY"]
