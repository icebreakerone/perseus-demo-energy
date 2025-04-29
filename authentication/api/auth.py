import base64
import json
import uuid
import time

import boto3  # type: ignore[import-untyped]
import requests
import jwt
from jwt import algorithms
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from fastapi import (
    HTTPException,
)

from .exceptions import AccessTokenDecodingError
from . import conf
from .logger import get_logger
from . import keystores
from ib1 import directory


logger = get_logger()


def _get_ory_secret_from_ssm():
    ssm = boto3.client("ssm")
    response = ssm.get_parameter(Name=conf.ORY_CLIENT_SECRET_PARAM, WithDecryption=True)
    return response["Parameter"]["Value"]


def get_session():
    session = requests.Session()
    if conf.ORY_CLIENT_ID and conf.ORY_CLIENT_SECRET:
        session.auth = (conf.ORY_CLIENT_ID, conf.ORY_CLIENT_SECRET)
    elif conf.ORY_CLIENT_SECRET_PARAM:
        session.auth = (conf.ORY_CLIENT_ID, _get_ory_secret_from_ssm())
    else:
        raise HTTPException(
            status_code=500,
            detail="Client ID and Secret not set",
        )
    return session


def create_state_token(context: dict | None = None) -> str:
    """
    A signed JWT token to be used as a state parameter in OAuth2 interactions with ory hydra
    """
    private_key = keystores.get_key(conf.JWT_SIGNING_KEY)
    payload = {
        "sub": "par",
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()),
        "exp": int(time.time()) + 600,
    }
    if context:
        payload.update(context)
    return jwt.encode(payload, private_key, algorithm="ES256")


def get_thumbprint(cert: x509.Certificate) -> str:
    """
    Returns the thumbprint of a certificate
    """
    thumbprint = str(
        base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).replace(b"=", b""),
        "utf-8",
    )
    return thumbprint


def decode_with_jwks(token: str, jwks_url: str) -> dict:
    """
    Validate a token using jwks_url
    """
    logger.info(f"Decoding token with jwks_url: {jwks_url}")
    jwks_client = jwt.PyJWKClient(jwks_url, headers={"User-Agent": "ib1/1.0"})

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
    external_token: str, client_certificate: x509.Certificate, external_oauth_url: str
) -> dict:
    logger.info("Creating enhanced access token")
    claims = decode_with_jwks(external_token, external_oauth_url)
    logger.info(f"Claims: {claims}")
    claims["cnf"] = {"x5t#S256": get_thumbprint(client_certificate)}
    claims["iss"] = conf.ISSUER_URL
    client_id = directory.extensions.decode_application(client_certificate)
    claims["client_id"] = client_id
    return claims


def encode_jwt(claims: dict) -> str:
    private_key = keystores.get_key(conf.JWT_SIGNING_KEY)
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
