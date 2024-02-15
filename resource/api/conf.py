import os

ENV = os.environ.get("ENV", "dev")
DIRNAME = os.path.dirname(os.path.realpath(__file__))
ISSUER_URL = os.environ.get("ISSUER_URL", "")
CLIENT_ID = "21653835348762"
CLIENT_SECRET = "uE4NgqeIpuSV_XejQ7Ds3jsgA1yXhjR1MXJ1LbPuyls"
OPEN_API_ROOT = "/dev" if ENV == "prod" else ""
