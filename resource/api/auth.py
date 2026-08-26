from typing import Tuple
import email.utils
import time
import ssl

import jwt.algorithms
import jwt

from .exceptions import (
    AccessTokenAudienceError,
    AccessTokenTimeError,
    AccessTokenDecodingError,
)
from . import conf
from ib1 import directory

from .logger import get_logger

logger = get_logger()


def decode_with_jwks(token: str, jwks_url: str, verify: bytes | None = None) -> dict:
    """
    Validate a token using jwks_url
    """

    # Work out how to integrate this with s3 / local
    context = None
    if verify:
        context = ssl.create_default_context(cadata=verify.decode())

    jwks_client = jwt.PyJWKClient(
        jwks_url, headers={"User-Agent": "ib1/1.0"}, ssl_context=context
    )
    try:
        header = jwt.get_unverified_header(token)
        key = jwks_client.get_signing_key(header["kid"]).key
    except KeyError:
        raise AccessTokenDecodingError("Token header has no key id")
    except jwt.exceptions.PyJWKClientError as e:
        raise AccessTokenDecodingError(f"Could not fetch the signing key: {e}")
    except jwt.InvalidTokenError as e:
        raise AccessTokenDecodingError(f"Invalid token: {e}")
    try:
        payload = jwt.decode(token, key, [header["alg"]])
    except jwt.ExpiredSignatureError:
        raise AccessTokenTimeError("Token expired")
    except jwt.InvalidTokenError as e:
        raise AccessTokenDecodingError(f"Invalid token: {e}")
    return payload


def check_token(
    client_certificate: str,
    token: str,
) -> Tuple[dict, dict]:
    """
    Check token is valid if:
        [ ] is valid
        [ ] has not expired,
        [ ] has not been revoked,
        [ ] has a client_id that matches the MTLS client certificate, and
        [ ] has a scope which matches the required license.
    If check succeeds, return a dict suitable to use as headers
    including Date, as well as the check token result
    """

    # Deny access to non-MTLS connections
    cert = directory.parse_cert(client_certificate)
    client_id = directory.extensions.decode_application(cert)

    decoded = decode_with_jwks(
        token,
        conf.AUTHENTICATION_SERVER
        + "/.well-known/jwks.json",  # Use unprotected endpoints
    )
    # Examples of tests to apply
    if decoded["client_id"] != client_id:
        raise AccessTokenAudienceError("Invalid Client ID")
    if decoded["exp"] < int(time.time()):
        raise AccessTokenTimeError("Token expired")
    if decoded["iat"] > int(time.time()):
        raise AccessTokenTimeError("Token issued in the future")
    headers = {}
    # FAPI requires that the resource server set the date header in the response
    headers["Date"] = email.utils.formatdate()
    return decoded, headers
