import json
import os
from typing import Optional
import time
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.backends import default_backend

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

def cert_response(cert_file="cert.pem", urlencoded=False):
    with open(f"{ROOT_DIR}/fixtures/{cert_file}", "rb") as cert_content:
        cert_data = cert_content.read()
    if urlencoded:
        cert = quote(cert_data.decode())
    else:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert

def introspection_response(
    exp: Optional[int] = None, iat: Optional[int] = None, active=True
):
    with open(f"{ROOT_DIR}/fixtures/jwt.json", "r") as jwt_file:
        introspection_response = json.load(jwt_file)
    if exp:
        introspection_response["exp"] = exp
    else:
        introspection_response["exp"] = time.time() + 20
    if iat:
        introspection_response["iat"] = iat
    else:
        introspection_response["iat"] = time.time() - 20
    introspection_response["active"] = active
    return introspection_response
