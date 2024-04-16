import os
import tempfile
import base64
import time
from urllib.parse import unquote
import logging
import email.utils
import uuid

from cryptography.hazmat.primitives import hashes
import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from . import conf

log = logging.getLogger(__name__)


class AccessTokenValidatorError(Exception):
    pass


class AccessTokenNoCertificateError(AccessTokenValidatorError):
    pass


class AccessTokenInactiveError(AccessTokenValidatorError):
    pass


class AccessTokenTimeError(AccessTokenValidatorError):
    pass


class AccessTokenCertificateError(AccessTokenValidatorError):
    pass


def parse_cert(client_certificate: str) -> x509.Certificate:
    """
    Given a certificate in the request context, return a Certificate object

    If a certificate is present, on our deployment it will be in request.headers['X-Amzn-Mtls-Clientcert']
    nb. the method and naming of passing the client certificate may vary depending on the deployment
    """
    cert_data = unquote(client_certificate).encode("utf-8")
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert


def _check_certificate(cert, introspection_response):
    if "cnf" in introspection_response:
        # thumbprint from introspection response
        try:
            sha256 = introspection_response["cnf"]["x5t#S256"]
        except KeyError:
            log.warning("No x5t#S256 claim in token response, unable to proceed!")
            raise AccessTokenCertificateError(
                "Token does not contain a certificate binding"
            )
        # thumbprint from presented client certificate
        fingerprint = str(
            base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).replace(
                b"=", b""
            ),
            "utf-8",
        )
        if fingerprint != sha256:
            log.warning(
                f"introspection response thumbprint {sha256} does not match "
                f"presented client cert thumbprint {fingerprint}"
            )
            raise AccessTokenCertificateError(
                "Token certificate binding does not match presented client cert"
            )
    else:
        # No CNF claim in the introspection response
        log.warning("No cnf claim in token response, unable to proceed!")
        raise AccessTokenCertificateError(
            "Token does not contain a certificate binding"
        )
    return True


def introspect(client_certificate: str, token: str) -> dict:
    """
    Introspection fails if:
        1. Querying the token introspection endpoint fails
        2. A token is returned with active: false
        3. Scope is specified, and the required scope is not in the token scopes
        4. Issued time is in the future
        5. Expiry time is in the past
        6. Certificate binding is enabled (default) and the fingerprint of the
           presented client cert isn't a match for the claim in the
           introspection response

    If introspection succeeds, return a dict suitable to use as headers
    including Date and x-fapi-interaction-id, as well as the introspection response
    """

    # Deny access to non-MTLS connections
    cert = parse_cert(client_certificate)
    if cert is None:
        log.warning("no client cert presented")
        raise AccessTokenNoCertificateError("No client certificate presented")
    introspection_response = jwt.decode(
        token, algorithms=["ES256"], options={"verify_signature": False}
    )
    introspection_response["active"] = True
    log.debug(f"introspection response {introspection_response}")

    # All valid introspection responses contain 'active', as the default behaviour
    # for an invalid token is to create a simple JSON {'active':false} response
    if (
        "active" not in introspection_response
        or introspection_response["active"] is not True
    ):
        raise AccessTokenInactiveError(
            "Invalid introspection response, does not contain 'active' or is not True"
        )

    now = time.time()
    if "iat" in introspection_response:
        # Issue time must be in the past
        if now < introspection_response["iat"]:
            log.warning("token issued in the future")
            raise AccessTokenTimeError("Token issued in the future")
    if "exp" in introspection_response:
        # Expiry time must be in the future
        if now > introspection_response["exp"]:
            log.warning("token expired")
            raise AccessTokenTimeError("Token expired")

    # If the token response contains a certificate binding then check it against the
    # current client cert. See https://tools.ietf.org/html/rfc8705

    _check_certificate(cert, introspection_response)
    # If we required a particular scope, check that it's in the list of scopes
    # defined for this token. Scope comparison is case insensitive
    # TODO enable scope checking
    # if scope:
    #     token_scopes = introspection_response['scope'].lower().split(' ') \
    #       if 'scope' in introspection_response else []
    #     log.debug(f'found scopes in token {token_scopes}')
    #     if scope.lower() not in token_scopes:
    #         log.warning(f'scope \'{scope}\' not in token scopes {token_scopes}')
    return introspection_response


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
        "iss": "https://perseus-demo-energy.ib1.org",
        "sub": subject,
        "aud": conf.CLIENT_ID,
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
        print("Returning conf.CERTS[type]")
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
