import base64
import jwt
import requests

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
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


def decode_with_jwks(token: str, url: str):

    # Define the JWKS URL
    JWKS_URL = f"{url}/.well-known/jwks.json"
    jwks = requests.get(JWKS_URL).json()
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    if key is None:
        raise AccessTokenDecodingError(f"Key ID {kid} not found in JWKS")
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("The public key is not an RSAPublicKey")
    # Decode and verify the token
    try:
        decoded_token = jwt.decode(
            token, key=public_key, algorithms=["RS256"], issuer=conf.OAUTH_URL
        )
    except jwt.ExpiredSignatureError:
        raise AccessTokenDecodingError("Token has expired!")
    except jwt.InvalidTokenError as e:
        raise AccessTokenDecodingError(f"Invalid token: {e}")
    return decoded_token


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

    numbers = public_key.public_numbers()

    # Convert EC public key to JWKS format
    return {
        "keys": [
            {
                "kty": "EC",
                "kid": "1",  # Change this when rotating keys
                "use": "sig",
                "alg": "ES256",  # Matches P-256 (secp256r1)
                "crv": "P-256",
                "x": base64url_encode(numbers.x.to_bytes(32, "big")),
                "y": base64url_encode(numbers.y.to_bytes(32, "big")),
            }
        ]
    }
