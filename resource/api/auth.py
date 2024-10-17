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
from . import conf
from .exceptions import (
    CertificateMissingError,
    AccessTokenCertificateError,
    AccessTokenAudienceError,
    AccessTokenTimeError,
)
from ib1 import directory

log = logging.getLogger(__name__)


def _check_certificate(cert: x509.Certificate, decoded_token: dict):

    if "cnf" in decoded_token:
        # thumbprint from introspection response
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
    client_certificate: str | None,
    token: str,
    aud: str,
    x_fapi_interaction_id: Optional[str] = None,
) -> Tuple[dict, dict]:
    """
    Check token fails if:
        1. Basic token checks (expiry, active, etc) fail
        2. The token is not bound to the client certificate
        3. The token is not correctly signed
    If check succeeds, return a dict suitable to use as headers
    including Date and x-fapi-interaction-id, as well as the check token result
    """

    # Deny access to non-MTLS connections
    if client_certificate is None:
        log.warning("no client cert presented")
        raise CertificateMissingError("No client certificate presented")
    cert = directory.parse_cert(client_certificate)
    client_id = str(
        cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    )
    # get the jwks endpoints from well-known configuration
    openid_config = get_openid_configuration(conf.ISSUER_URL)
    jwks_uri = openid_config["jwks_uri"]
    jwks_client = jwt.PyJWKClient(jwks_uri)
    # ssl._create_default_https_context = (
    #     ssl._create_unverified_context
    # )  # Must be removed for production
    header = jwt.get_unverified_header(token)
    key = jwks_client.get_signing_key(header["kid"]).key
    decoded = jwt.decode(token, key, [header["alg"]], audience=aud)
    # Examples of tests to apply
    if decoded["client_id"] != client_id:
        raise AccessTokenAudienceError("Invalid Client ID")
    if decoded["aud"] != aud:
        raise AccessTokenAudienceError("Invalid Audience")
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
