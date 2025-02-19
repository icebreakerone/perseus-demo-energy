import base64
import json

import jwt
from jwt import algorithms
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


from .exceptions import AccessTokenDecodingError
from . import conf
from .logger import logger
from . import keystores
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


def decode_with_jwks(token: str, jwks_url: str) -> dict:
    """
    Validate a token using jwks_url
    """
    logger.info(f"Decoding token with jwks_url: {jwks_url}")
    jwks_client = jwt.PyJWKClient(jwks_url, headers={"User-Agent": "ib1/1.0"})
    logger.error(f"Could not connect to JWKS URL: {jwks_url}")

    header = jwt.get_unverified_header(token)
    key = jwks_client.get_signing_key(header["kid"]).key
    try:
        payload = jwt.decode(token, key, [header["alg"]])
    except jwt.ExpiredSignatureError:
        raise AccessTokenDecodingError("Token has expired!")
    except jwt.InvalidTokenError as e:
        raise AccessTokenDecodingError(f"Invalid token: {e}")

    return payload


def create_enhanced_access_token(
    external_token: str, client_certificate: str, external_oauth_url: str
) -> str:
    logger.info("Creating enhanced access token")
    claims = decode_with_jwks(external_token, external_oauth_url)
    logger.info(f"Claims: {claims}")
    claims["cnf"] = {"x5t#S256": get_thumbprint(client_certificate)}
    client_id = directory.extensions.decode_application(
        directory.parse_cert(client_certificate)
    )
    claims["client_id"] = client_id
    private_key = keystores.get_key(conf.JWT_SIGNING_KEY)
    print(private_key)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("The private key is not an EllipticCurvePrivateKey")
    return jwt.encode(claims, private_key, algorithm="ES256", headers={"kid": "1"})


# Convert integers to base64url format
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def create_jwks(key_path: str):
    # Load existing EC private key from file
    private_key = keystores.get_key(key_path)
    # Extract the public key
    public_key = private_key.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("The public key is not an EllipticCurvePublicKey")

    jwks = json.loads(algorithms.ECAlgorithm.to_jwk(public_key))
    jwks["kid"] = "1"  # Change this when rotating keys
    jwks["use"] = "sig"
    jwks["alg"] = "ES256"
    return {"keys": [jwks]}
