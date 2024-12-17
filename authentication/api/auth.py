import os
import tempfile
import base64

from cryptography.hazmat.primitives import hashes

import jwt

from . import conf
from .logger import logger
from ib1 import directory


def get_thumbprint(cert: str) -> str:
    """
    Returns the thumbprint of a certificate
    """
    parsed_cert = directory.parse_cert(cert)
    thumbprint = str(
        base64.urlsafe_b64encode(parsed_cert.fingerprint(hashes.SHA256())).replace(
            b"=", b""
        ),
        "utf-8",
    )
    return thumbprint


def create_enhanced_access_token(claims: dict, client_certificate: str) -> str:
    logger.info("Creating enhanced access token")
    logger.info(f"Claims: {claims}")
    claims["cnf"] = {"x5t#S256": get_thumbprint(client_certificate)}
    client_id = directory.extensions.decode_application(
        directory.parse_cert(client_certificate)
    )
    claims["client_id"] = client_id
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
