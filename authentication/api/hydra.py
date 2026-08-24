"""
All interaction with the upstream Ory Hydra OAuth2 server.

Hydra runs on Ory Network rather than being self hosted, so we cannot configure
what it puts in an error body. In particular `error_debug` can carry internal
detail such as `sql: no rows in result set`. Everything returned to a caller is
therefore built from an allowlist, and anything unrecognised is dropped.
"""

import requests

from . import conf
from .auth import get_session
from .exceptions import OAuthError
from .logger import get_logger

logger = get_logger()

# Only these fields are ever copied out of an upstream error body
FORWARDED_FIELDS = ("error_description", "error_hint")

MAX_DESCRIPTION_LENGTH = 200

UPSTREAM_ERROR = "Authorization server error"
UPSTREAM_UNAVAILABLE = "Authorization server temporarily unavailable"
UPSTREAM_TIMEOUT = "Authorization server did not respond in time"

# Errors the caller can act on. The status is ours, not Hydra's: `invalid_client`
# and `unauthorized_client` describe the client authenticated *at Hydra*, which
# is this service, so forwarding Hydra's 400 or 401 would blame the caller for
# our misconfiguration.
CALLER_ERRORS = {
    "invalid_request": 400,
    "invalid_grant": 400,
    "invalid_scope": 400,
    "unsupported_grant_type": 400,
    "unsupported_token_type": 400,  # revocation, RFC 7009
    "access_denied": 400,
}

SERVICE_ERRORS = {
    "invalid_client": 502,
    "unauthorized_client": 502,
    "server_error": 502,
    "temporarily_unavailable": 503,
}


def _clean(value: object) -> str | None:
    """
    Accept a field from an upstream body only if it is a plain string, with
    control characters removed and a length cap.
    """
    if not isinstance(value, str):
        return None
    cleaned = "".join(character for character in value if character.isprintable())
    cleaned = cleaned.strip()
    if not cleaned:
        return None
    return cleaned[:MAX_DESCRIPTION_LENGTH]


def _error_code(response: requests.Response) -> tuple[str | None, dict]:
    """
    Read the OAuth2 error code from an upstream response.

    Returns the code and the parsed body. The code is None if the body is not
    JSON, is not an object, or carries no usable `error` string. Ory returns a
    different envelope for non OAuth2 paths, where `error` is an object rather
    than a string, so the type check matters.
    """
    try:
        body = response.json()
    except ValueError:
        return None, {}
    if not isinstance(body, dict):
        return None, {}
    code = body.get("error")
    if not isinstance(code, str) or not code.strip():
        return None, body
    return code.strip(), body


def upstream_error(response: requests.Response) -> OAuthError:
    """
    Convert a non-200 response from Hydra into an error safe to return.

    Descriptions are forwarded only for errors the caller can act on. For our
    own misconfiguration, or an upstream fault, the caller gets a fixed message
    and the detail goes to the logs.
    """
    code, body = _error_code(response)

    if code is None:
        logger.error(
            f"Unparseable response from Ory Hydra, status {response.status_code}, "
            f"body {response.text[:MAX_DESCRIPTION_LENGTH]!r}"
        )
        return OAuthError(502, "server_error", UPSTREAM_ERROR)

    if code in CALLER_ERRORS or (code not in SERVICE_ERRORS and response.status_code == 400):
        forwarded = {field: _clean(body.get(field)) for field in FORWARDED_FIELDS}
        status = CALLER_ERRORS.get(code, 400)
        logger.warning(
            f"Ory Hydra rejected the request, status {response.status_code}, error {code}"
        )
        return OAuthError(
            status,
            code,
            forwarded["error_description"],
            forwarded["error_hint"],
        )

    if code == "invalid_client":
        # The single most likely cause of a total outage after a credential
        # rotation, so name what an operator needs to check.
        logger.error(
            "Ory Hydra rejected our client credentials (invalid_client). "
            "Check ORY_CLIENT_ID and ORY_CLIENT_SECRET. "
            f"Upstream said: {_clean(body.get('error_description'))}"
        )
    else:
        logger.error(
            f"Ory Hydra returned {code}, status {response.status_code}, "
            f"description {_clean(body.get('error_description'))!r}, "
            f"hint {_clean(body.get('error_hint'))!r}"
        )

    if code == "temporarily_unavailable":
        return OAuthError(503, "temporarily_unavailable", UPSTREAM_UNAVAILABLE)
    return OAuthError(502, "server_error", UPSTREAM_ERROR)


def _post(url: str, payload: dict) -> requests.Response:
    """
    Post to Hydra, converting a transport failure into an OAuthError.
    """
    session = get_session()
    try:
        return session.post(url, data=payload, timeout=conf.ORY_TIMEOUT)
    except requests.exceptions.Timeout:
        logger.warning(f"Timed out after {conf.ORY_TIMEOUT}s calling {url}")
        raise OAuthError(504, "server_error", UPSTREAM_TIMEOUT)
    except requests.exceptions.RequestException:
        logger.exception(f"Could not reach {url}")
        raise OAuthError(502, "server_error", UPSTREAM_ERROR)


def request_token(payload: dict) -> dict:
    """
    Exchange a grant at Hydra's token endpoint, returning the parsed response.
    """
    response = _post(conf.ORY_TOKEN_ENDPOINT, payload)
    if response.status_code != 200:
        raise upstream_error(response)
    try:
        return response.json()
    except ValueError:
        logger.error("Ory Hydra returned 200 with a body that is not JSON")
        raise OAuthError(502, "server_error", UPSTREAM_ERROR)


def revoke_token(payload: dict) -> None:
    """
    Revoke a token at Hydra's revocation endpoint.
    """
    response = _post(f"{conf.ORY_URL}/oauth2/revoke", payload)
    if response.status_code != 200:
        raise upstream_error(response)
