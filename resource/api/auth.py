import logging
import urllib.parse
import uuid
from typing import Optional, Tuple
import email.utils
import time
import base64
from cryptography.hazmat.primitives import hashes
import requests
import jwt
from cryptography import x509
from .exceptions import (
    AccessTokenCertificateError,
    AccessTokenAudienceError,
    AccessTokenTimeError,
)
from ib1 import directory

log = logging.getLogger(__name__)


def _check_certificate(cert: x509.Certificate, decoded_token: dict):

    if "cnf" in decoded_token:
        # thumbprint from token
        try:
            sha256 = decoded_token["cnf"]["x5t#S256"]
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
                f"Token thumbprint {sha256} does not match "
                f"presented client cert thumbprint {fingerprint}"
            )
            raise AccessTokenCertificateError(
                "Token certificate binding does not match presented client cert"
            )
    else:
        # No CNF claim in the token
        log.warning("No cnf claim in token response, unable to proceed!")
        raise AccessTokenCertificateError(
            "Token does not contain a certificate binding"
        )
    return True


def get_openid_configuration(issuer_url: str) -> dict:
    """
    Get the well-known configuration for a given issuer URL
    """
    response = requests.get(
        url=urllib.parse.urljoin(issuer_url, "/.well-known/openid-configuration"),
        verify=False,
    )
    response.raise_for_status()
    return response.json()


def check_token(
    client_certificate: str,
    token: str,
    aud: str,
    x_fapi_interaction_id: Optional[str] = None,
) -> Tuple[dict, dict]:
    """
    Check token is valid if:
        [ ] is valid
        [ ] has not expired,
        [ ] has not been revoked,
        [ ] has a client_id that matches the MTLS client certificate, and
        [ ] has a scope which matches the required licence.
    If check succeeds, return a dict suitable to use as headers
    including Date and x-fapi-interaction-id, as well as the check token result
    """

    # Deny access to non-MTLS connections
    cert = directory.parse_cert(client_certificate)
    client_id = directory.extensions.decode_application(cert)

    decoded = jwt.decode(
        token,
        options={"verify_signature": False},
    )
    # Examples of tests to apply
    if decoded["client_id"] != client_id:
        raise AccessTokenAudienceError("Invalid Client ID")
    if decoded["exp"] < int(time.time()):
        raise AccessTokenTimeError("Token expired")
    if decoded["iat"] > int(time.time()):
        raise AccessTokenTimeError("Token issued in the future")
    _check_certificate(cert, decoded)
    headers = {}
    # FAPI requires that the resource server set the date header in the response
    headers["Date"] = email.utils.formatdate()

    # Get FAPI interaction ID if set, or create a new one otherwise
    if x_fapi_interaction_id is None:
        x_fapi_interaction_id = str(uuid.uuid4())
        log.debug(f"issuing new interaction ID = {x_fapi_interaction_id}")
    else:
        log.debug(f"using existing interaction ID = {x_fapi_interaction_id}")
    headers["x-fapi-interaction-id"] = x_fapi_interaction_id
    return decoded, headers
