import logging
import urllib.parse
import uuid
from typing import Optional, Tuple
import requests


from . import conf


log = logging.getLogger(__name__)


class AccessTokenValidatorError(Exception):
    pass


class AccessTokenNoCertificateError(AccessTokenValidatorError):
    pass


class AccessTokenInactiveError(AccessTokenValidatorError):
    pass


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


def check_token(token: str, client_certificate: str) -> dict:
    openid_config = get_openid_configuration(conf.ISSUER_URL)
    introspection_endpoint = openid_config["introspection_endpoint"]
    if (
        "localhost" in introspection_endpoint
    ):  # Bit of messing about for docker, consider bringing accounting app into the same project
        introspection_endpoint = introspection_endpoint.replace(
            "https://localhost:8000", conf.ISSUER_URL
        )
    log.debug("Token type", type(token))
    try:
        response = requests.post(
            url=introspection_endpoint,
            json={"token": token, "client_certificate": client_certificate},
            auth=(conf.OAUTH_CLIENT_ID, conf.CLIENT_SECRET),
            verify=False,
        )
        if response.status_code != 200:
            log.error(f"introspection request failed: {response.text}")
            raise AccessTokenValidatorError("Introspection request failed")

    except requests.exceptions.RequestException as e:
        log.error(f"introspection request failed: {e}")
        raise AccessTokenValidatorError("Introspection request failed")
    return response.json()


def introspect(
    client_certificate: str, token: str, x_fapi_interaction_id: Optional[str] = None
) -> Tuple[dict, dict]:
    """
    Introspection fails if:
        1. Querying the token introspection endpoint fails
        2. A token is returned with active: false
        3. Scope is specified, and the required scope is not in the token scopes
        4. No client certificate is presented
    If introspection succeeds, return a dict suitable to use as headers
    including Date and x-fapi-interaction-id, as well as the introspection response
    """

    # Deny access to non-MTLS connections
    if client_certificate is None:
        log.warning("no client cert presented")
        raise AccessTokenNoCertificateError("No client certificate presented")
    introspection_response = check_token(token, client_certificate)
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
    headers = {}
    # FAPI requires that the resource server set the date header in the response
    # headers["Date"] = email.utils.formatdate()

    # Get FAPI interaction ID if set, or create a new one otherwise
    if x_fapi_interaction_id is None:
        x_fapi_interaction_id = str(uuid.uuid4())
        log.debug(f"issuing new interaction ID = {x_fapi_interaction_id}")
    else:
        log.debug(f"using existing interaction ID = {x_fapi_interaction_id}")
    headers["x-fapi-interaction-id"] = x_fapi_interaction_id
    return introspection_response, headers
