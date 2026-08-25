"""
Unit tests for the upstream error mapper.

These exercise the pure mapping, with no FastAPI involved.
"""

import json
from unittest.mock import MagicMock

import pytest

from api import hydra
from tests import (  # noqa
    HYDRA_HERODOT_404,
    HYDRA_INVALID_CLIENT,
    HYDRA_INVALID_GRANT,
    HYDRA_SERVER_ERROR,
    HYDRA_UNSUPPORTED_TOKEN_TYPE,
    PROXY_HTML_502,
)


def hydra_response(body, status_code=400):
    """A requests.Response stand-in carrying the given body."""
    response = MagicMock()
    response.status_code = status_code
    if isinstance(body, str):
        response.text = body
        response.json.side_effect = json.decoder.JSONDecodeError("no", body, 0)
    else:
        response.text = json.dumps(body)
        response.json.return_value = body
    return response


@pytest.mark.parametrize(
    "code,upstream_status,expected_status",
    [
        ("invalid_request", 400, 400),
        ("invalid_grant", 400, 400),
        ("invalid_scope", 400, 400),
        ("unsupported_grant_type", 400, 400),
        ("unsupported_token_type", 400, 400),
        ("access_denied", 400, 400),
        # These describe the client authenticated at Hydra, which is us
        ("unauthorized_client", 400, 502),
        ("invalid_client", 401, 502),
        ("server_error", 500, 502),
        ("temporarily_unavailable", 503, 503),
    ],
)
def test_status_mapping(code, upstream_status, expected_status):
    """Each error code maps to the status in the agreed table."""
    error = hydra.upstream_error(
        hydra_response({"error": code, "error_description": "x"}, upstream_status)
    )

    assert error.status_code == expected_status


def test_caller_error_forwards_description_and_hint():
    """An error the caller can act on carries Hydra's own wording through."""
    error = hydra.upstream_error(hydra_response(HYDRA_INVALID_GRANT, 400))

    assert error.status_code == 400
    assert error.error == "invalid_grant"
    assert "authorization grant" in error.error_description
    assert error.error_hint == HYDRA_INVALID_GRANT["error_hint"]


def test_our_fault_error_withholds_upstream_wording():
    """invalid_client is our misconfiguration, so the caller is told nothing."""
    error = hydra.upstream_error(hydra_response(HYDRA_INVALID_CLIENT, 401))

    assert error.status_code == 502
    assert error.error == "server_error"
    assert error.error_description == hydra.UPSTREAM_ERROR
    assert error.error_hint is None
    # The whole error, not just the description, to catch a future field
    rendered = repr(error.body())
    assert "sql: no rows" not in rendered
    assert "does not exist" not in rendered


def test_error_debug_is_never_forwarded():
    """error_debug carries internal detail and is not in the allowlist."""
    error = hydra.upstream_error(hydra_response(HYDRA_SERVER_ERROR, 500))

    assert "invalid memory address" not in repr(error.body())


def test_status_code_field_is_not_forwarded():
    """fosite duplicates the status into the body; we ignore it."""
    error = hydra.upstream_error(hydra_response(HYDRA_INVALID_GRANT, 400))

    assert "status_code" not in error.body()


def test_nested_error_object_is_treated_as_unparseable():
    """Ory's herodot envelope has an object in `error`, not a string."""
    error = hydra.upstream_error(hydra_response(HYDRA_HERODOT_404, 404))

    assert error.status_code == 502
    assert error.error == "server_error"
    assert "404 page not found" not in repr(error.body())


def test_html_body_is_treated_as_unparseable():
    """A proxy in front of Ory can return HTML."""
    error = hydra.upstream_error(hydra_response(PROXY_HTML_502, 502))

    assert error.status_code == 502
    assert error.error == "server_error"
    assert "Bad Gateway" not in repr(error.body())


def test_empty_body_is_treated_as_unparseable():
    error = hydra.upstream_error(hydra_response("", 400))

    assert error.status_code == 502
    assert error.error == "server_error"


def test_json_without_an_error_key_is_treated_as_unparseable():
    error = hydra.upstream_error(hydra_response({"something": "else"}, 400))

    assert error.status_code == 502


def test_unrecognised_code_on_a_400_is_forwarded():
    """An error code we do not know, but a status that blames the caller."""
    error = hydra.upstream_error(
        hydra_response({"error": "some_new_ory_code", "error_description": "why"}, 400)
    )

    assert error.status_code == 400
    assert error.error == "some_new_ory_code"
    assert error.error_description == "why"


def test_unrecognised_code_on_another_status_is_not_forwarded():
    error = hydra.upstream_error(
        hydra_response({"error": "some_new_ory_code", "error_description": "why"}, 500)
    )

    assert error.status_code == 502
    assert error.error == "server_error"
    assert "why" not in repr(error.body())


def test_non_string_description_is_dropped_not_stringified():
    error = hydra.upstream_error(
        hydra_response({"error": "invalid_grant", "error_description": {"a": 1}}, 400)
    )

    assert error.error_description is None
    assert "{'a': 1}" not in repr(error.body())


def test_long_description_is_truncated():
    error = hydra.upstream_error(
        hydra_response({"error": "invalid_grant", "error_description": "x" * 400}, 400)
    )

    assert len(error.error_description) == hydra.MAX_DESCRIPTION_LENGTH


def test_control_characters_are_stripped():
    error = hydra.upstream_error(
        hydra_response(
            {"error": "invalid_grant", "error_description": "line\x00one\x1b[31m"}, 400
        )
    )

    assert "\x00" not in error.error_description
    assert "\x1b" not in error.error_description
