import logging
import urllib.parse
import uuid
from typing import Optional, Tuple
import email.utils
import time
from urllib.parse import unquote
import ssl
import base64
from cryptography.hazmat.primitives import hashes
import requests
import jwt
from cryptography import x509

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


class AccessTokenAudienceError(AccessTokenValidatorError):
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
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert


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
        raise AccessTokenNoCertificateError("No client certificate presented")
    cert = parse_cert(client_certificate)
    client_id = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    # get the jwks endpoints from well-known configuration
    openid_config = get_openid_configuration(conf.ISSUER_URL)
    jwks_uri = openid_config["jwks_uri"]
    jwks_client = jwt.PyJWKClient(jwks_uri)
    ssl._create_default_https_context = (
        ssl._create_unverified_context
    )  # Must be removed for production
    header = jwt.get_unverified_header(token)
    key = jwks_client.get_signing_key(header["kid"]).key
    decoded = jwt.decode(token, key, [header["alg"]], audience=client_id)
    # Examples of tests to apply
    if decoded["aud"] != client_id:
        raise AccessTokenAudienceError("Invalid audience")
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
