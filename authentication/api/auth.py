import os
import tempfile
import base64
import time
from urllib.parse import unquote
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

import jwt
from cryptography import x509

from . import conf

log = logging.getLogger(__name__)


def parse_cert(client_certificate: str) -> x509.Certificate:
    """
    Given a certificate in the request context, return a Certificate object

    If a certificate is present, on our deployment it will be in request.headers['X-Amzn-Mtls-Clientcert']
    nb. the method and naming of passing the client certificate may vary depending on the deployment
    """
    cert_data = unquote(client_certificate).encode("utf-8")
    print(cert_data)
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert


def get_thumbprint(cert: str) -> str:
    """
    Returns the thumbprint of a certificate
    """
    parsed_cert = parse_cert(cert)
    thumbprint = str(
        base64.urlsafe_b64encode(parsed_cert.fingerprint(hashes.SHA256())).replace(
            b"=", b""
        ),
        "utf-8",
    )
    return thumbprint


def create_id_token(subject="platform_user") -> str:
    claims = {
        "iss": f"{conf.ISSUER_URL}",
        "sub": subject,
        "aud": conf.OAUTH_CLIENT_ID,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "kid": 1,
        # "nonce": "abc123",  # nonce is optional for authorisation code flow
    }
    private_key_path = get_key("key")
    with open(private_key_path, "rb") as f:
        private_key = f.read()
    return jwt.encode(claims, private_key, algorithm="ES256", headers={"kid": "1"})


def create_enhanced_access_token(claims: dict, client_certificate: str) -> str:
    claims["cnf"] = {"x5t#S256": get_thumbprint(client_certificate)}
    private_key_path = get_key("key")
    with open(private_key_path, "rb") as f:
        private_key = f.read()
    return jwt.encode(claims, private_key, algorithm="ES256")


def get_key(type: str = "key") -> str:
    """
    Returns the local path to a certificate if it exists,
    or the tmp path to the matching certificate stored as an env var
    """
    if conf.CERTS[type] and os.path.exists(conf.CERTS[type]):
        return conf.CERTS[type]
    secret = os.environ.get(f"SERVER_{type.upper()}")
    fp = tempfile.NamedTemporaryFile(delete=False)
    if secret is not None:
        fp.write(secret.encode("utf-8"))
    else:
        raise FileNotFoundError(f"Could not find the {type} in the environment")
    return fp.name


def create_jwks(public_key_pem_path, kid=1):
    # Read the public key from the PEM file
    with open(public_key_pem_path, "r") as f:
        public_key_pem = f.read()
    public_key_lines = public_key_pem.strip().split("\n")[
        1:-1
    ]  # Remove header and footer lines
    public_key_base64 = "".join(public_key_lines)
    public_key_der = base64.b64decode(public_key_base64)

    # Extract x and y coordinates from DER encoded public key
    public_key_x = int.from_bytes(public_key_der[27 : 27 + 32], byteorder="big")
    public_key_y = int.from_bytes(public_key_der[59 : 59 + 32], byteorder="big")

    # Construct the JWK (JSON Web Key)
    jwk = {
        "kty": "EC",
        "alg": "ES256",
        "use": "sig",
        "kid": f"{kid}",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(
            public_key_x.to_bytes(32, byteorder="big")
        ).decode("utf-8"),
        "y": base64.urlsafe_b64encode(
            public_key_y.to_bytes(32, byteorder="big")
        ).decode("utf-8"),
    }

    # Create the JWKS (JSON Web Key Set)
    jwks = {"keys": [jwk]}

    return jwks


def require_role(role_name, quoted_certificate) -> bool:
    """Check that the certificate presented by the client includes the given role,
    throwing an exception if the requirement isn't met. Assumes the proxy has verified
    the certificate.
    """
    # Extract a list of roles from the certificate
    cert = parse_cert(quoted_certificate)
    return role_name in [
        ou.value
        for ou in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    ]
