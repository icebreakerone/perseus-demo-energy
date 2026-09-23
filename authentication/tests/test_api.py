import json
import os
import sys
from unittest.mock import patch, MagicMock
import time
import datetime
from urllib.parse import parse_qs, urlparse

import pytest
import requests
import responses
from fastapi.testclient import TestClient

from api.main import app, conf
from api import auth
from api.logger import get_logger
from tests import (
    client_certificate,
    CLIENT_ID,
    HYDRA_INVALID_CLIENT,
    HYDRA_INVALID_GRANT,
    HYDRA_UNSUPPORTED_TOKEN_TYPE,
    SCHEME_URL,
    TEST_ROLE,
)

from tests.test_permissions import stored_permission

logger = get_logger()
client = TestClient(app)
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MOCK_TOKEN = "mock_enhanced_access_token"
MOCK_ENHANCED_TOKEN = "mock_enhanced_access_token"
MOCK_REFRESH_TOKEN = "mock_refresh_token"
LICENSE = conf.ENERGY_CONSUMPTION_LICENSE_URL
MOCK_CERT = "mock_client_cert"


class FakeConf:
    def __init__(self) -> None:
        self.DIRNAME = conf.DIRNAME
        self.ISSUER_URL = os.environ.get(
            "ISSUER_URL", "https://perseus-demo-authentication.ib1.org"
        )
        self.MTLS_URL = os.environ.get(
            "MTLS_URL", "https://mtls.perseus-demo-authentication.ib1.org"
        )
        self.ORY_CLIENT_SECRET = "123abc"
        self.ORY_URL = "https://test-oauth.io"
        self.ORY_CLIENT_ID = "abc-123"
        self.ORY_AUTHORIZATION_ENDPOINT = f"{self.ORY_URL}/oauth2/auth"
        self.JWKS_URL = f"{self.ORY_URL}/.well-known/jwks.json"
        self.JWT_SIGNING_KEY = f"{ROOT_DIR}/fixtures/server-signing-private-key.pem"
        self.ORY_TOKEN_ENDPOINT = f"{self.ORY_URL}/oauth2/token"
        self.REDIRECT_URI = "https://test-accounting.org/callback"
        self.CALLBACK_URL = "https://perseus-demo-authentication.ib1.org/api/v1/callback"
        self.REDIS_HOST = "redis"
        self.PROVIDER_ROLE = TEST_ROLE
        self.ORY_TIMEOUT = 10.0


def hydra_error(body, status_code):
    """A mocked Hydra response carrying a realistic error body."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = json.dumps(body)
    mock_response.json.return_value = body
    return mock_response


TOKEN_REQUEST_DATA = {
    "grant_type": "authorization_code",
    "redirect_uri": "https://client.app/callback",
    "code_verifier": "mock_verifier",
    "code": "mock_code",
}


@pytest.fixture
def log_lines():
    """
    Capture loguru output. loguru does not feed pytest's caplog, so the sink has
    to be added by hand.
    """
    from api.logger import get_logger

    captured: list = []
    log = get_logger()
    sink_id = log.add(captured.append, format="{message}")
    yield captured
    log.remove(sink_id)


@pytest.fixture
def mock_directory():
    """Mock directory methods for cert parsing and role validation."""
    with patch(
        "api.main.directory.parse_cert", return_value=MOCK_CERT
    ) as mock_parse_cert, patch("api.main.directory.require_role") as mock_require_role:
        yield mock_parse_cert, mock_require_role


@pytest.fixture
def mock_auth():
    """Mock JWT enhancement function."""
    with patch(
        "api.main.auth.encode_jwt", return_value=MOCK_ENHANCED_TOKEN
    ) as mock_auth:
        yield mock_auth


@pytest.fixture
def jwt_signing_jwks():
    return auth.create_jwks(f"{ROOT_DIR}/fixtures/server-signing-private-key.pem")


# Mock the redis server, as pushed_authorization_request() uses it
@patch("api.store.redis_connection")
@patch("api.main.store.store_callback")
@patch("api.main.auth.create_state_token")
def test_pushed_authorization_request(
    mock_create_state_token, mock_store_callback, mock_redis_connection
):
    cert_urlencoded = client_certificate()
    mock_redis = MagicMock()
    mock_redis.set.return_value = True
    mock_redis_connection.return_value = mock_redis
    mock_create_state_token.return_value = "mock_state_token"
    response = client.post(
        "/api/v1/par",
        data={
            "client_id": CLIENT_ID,
            "redirect_uri": "https://mobile.example.com/cb",
            "code_challenge": "W78hCS0q72DfIHa...kgZkEJuAFaT4",
            "scope": "profile",
            "response_type": "code",
            "state": "WFqUWTVvX49tM",
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 201
    assert "request_uri" in response.json()
    mock_store_callback.assert_called_once_with(
        "mock_state_token", "https://mobile.example.com/cb", "WFqUWTVvX49tM"
    )


@patch("api.store.redis_connection")
@patch("api.main.store.store_callback")
@patch("api.main.auth.create_state_token")
def test_pushed_authorization_request_without_state(
    mock_create_state_token, mock_store_callback, mock_redis_connection
):
    """A client that sends no state has none stored to be returned"""
    mock_redis_connection.return_value = MagicMock()
    mock_create_state_token.return_value = "mock_state_token"
    response = client.post(
        "/api/v1/par",
        data={
            "redirect_uri": "https://mobile.example.com/cb",
            "code_challenge": "W78hCS0q72DfIHa...kgZkEJuAFaT4",
            "scope": "profile",
            "response_type": "code",
        },
        headers={"x-amzn-mtls-clientcert-leaf": client_certificate()},
    )

    assert response.status_code == 201
    mock_store_callback.assert_called_once_with(
        "mock_state_token", "https://mobile.example.com/cb", None
    )


@patch("api.main.conf", FakeConf())
@patch("api.store.get_request")
def test_authorization_code(mock_get_request):
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    redirect = "http://anywhere.com"
    mock_get_request.return_value = {
        "client_id": CLIENT_ID,
        "redirect_uri": redirect,
        "scope": "profile",
        "code_challenge": "123123123",
        "state": "123123123",
    }
    response = client.get(
        "/api/v1/authorize",
        params={
            "client_id": CLIENT_ID,
            "request_uri": "urn:ietf:params:oauth:request_uri:O38VUUUC1quZR59Fhx0TrTLZGX4",
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "Location" in response.headers
    location = response.headers["Location"]
    assert f"redirect_uri={FakeConf().CALLBACK_URL}" in location
    # The client sends a License URL alone, and this server asks Hydra for the
    # offline_access that a refresh token depends on
    assert parse_qs(urlparse(location).query)["scope"] == ["profile offline_access"]


@pytest.mark.parametrize(
    "scope, expected",
    [
        (LICENSE, f"{LICENSE} offline_access"),
        (f"{LICENSE} offline_access", f"{LICENSE} offline_access"),
        ("offline_access", "offline_access"),
    ],
    ids=["license-only", "already-asked-for", "offline-only"],
)
def test_upstream_scope_asks_for_offline_access_once(scope, expected):
    assert auth.upstream_scope(scope) == expected


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@patch("api.auth.decode_with_jwks")
@patch("api.main.permissions")
@responses.activate
def test_token_without_a_refresh_token_is_an_upstream_error(
    mock_permissions, mock_decode_with_jwks
):
    """
    A Permission is renewed by refreshing, so a token response Hydra sends
    without a refresh token is an upstream failure, not a 500 from validating
    our own response model.
    """
    now = int(time.time())
    mock_decode_with_jwks.return_value = {
        "client_id": CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
        "sub": "mock_user",
        "iss": FakeConf().ISSUER_URL,
        "scp": [LICENSE],
    }
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        json={"access_token": MOCK_TOKEN},
        status=200,
    )
    response = client.post(
        "/api/v1/authorize/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.app/callback",
            "code_verifier": "mock_verifier",
            "code": "mock_code",
        },
        headers={"x-amzn-mtls-clientcert-leaf": client_certificate(roles=[TEST_ROLE])},
    )

    assert response.status_code == 502
    assert response.json()["error"] == "server_error"
    mock_permissions.store_permission.assert_not_called()


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@patch("api.auth.decode_with_jwks")
@patch("api.main.permissions")
@responses.activate
def test_token_success(mock_permissions, mock_decode_with_jwks, mock_auth):
    """Test a successful token request."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    now = int(time.time())
    mock_decode_with_jwks.return_value = {
        "client_id": CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
        "sub": "mock_user",
        "iss": FakeConf().ISSUER_URL,
        "scp": ["https://directory.ib1.org/roles/test"],
        "ext": {},
    }
    mock_permissions.return_value = True
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        json={"access_token": MOCK_TOKEN, "refresh_token": MOCK_REFRESH_TOKEN},
        status=200,
    )
    response = client.post(
        "/api/v1/authorize/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.app/callback",
            "code_verifier": "mock_verifier",
            "code": "mock_code",
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )
    logger.info(response.status_code)
    logger.info(response.json())
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["access_token"] == MOCK_TOKEN
    # RFC 6749 section 5.1 requires token_type
    assert json_response["token_type"] == "Bearer"
    assert json_response["expires_in"] == 3600
    # A new grant creates the Permission Record
    mock_permissions.store_permission.assert_called_once()
    mock_permissions.store_refreshed_permission.assert_not_called()


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@patch("api.auth.decode_with_jwks")
@patch("api.permissions.write_permission")
@patch("api.permissions.get_permission_by_token")
@responses.activate
def test_token_refresh_updates_the_permission(
    mock_get_permission_by_token, mock_write_permission, mock_decode_with_jwks
):
    """A refresh by the owning client keeps the grant and records the new token"""
    stored = stored_permission(client=CLIENT_ID)
    mock_get_permission_by_token.return_value = stored
    now = int(time.time())
    mock_decode_with_jwks.return_value = {
        "exp": now + 3600,
        "iat": now,
        "sub": stored.account,
        "scp": [stored.license, "offline_access"],
    }
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        json={"access_token": MOCK_TOKEN, "refresh_token": "new-refresh-token"},
        status=200,
    )
    response = client.post(
        "/api/v1/authorize/token",
        data={"grant_type": "refresh_token", "refresh_token": "current-refresh-token"},
        headers={"x-amzn-mtls-clientcert-leaf": client_certificate(roles=[TEST_ROLE])},
    )

    assert response.status_code == 200
    assert response.json()["refresh_token"] == "new-refresh-token"
    mock_get_permission_by_token.assert_called_once_with("current-refresh-token")
    written = mock_write_permission.call_args[0][0]
    assert written.refreshToken == "new-refresh-token"
    assert written.lastGranted == stored.lastGranted
    assert written.expires == stored.expires
    assert written.evidenceId == stored.evidenceId


@pytest.mark.parametrize(
    "stored",
    [
        None,
        stored_permission(client="https://directory.core.ib1.org/application/other"),
        stored_permission(client=CLIENT_ID, revoked=datetime.datetime.now(datetime.timezone.utc)),
    ],
    ids=["unknown", "other-client", "revoked"],
)
@patch("api.main.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@patch("api.permissions.get_permission_by_token")
@responses.activate
def test_token_refresh_refused_before_hydra(mock_get_permission_by_token, stored):
    """
    A refused refresh never reaches Hydra, which would rotate the token and
    leave the owning client unable to use it
    """
    mock_get_permission_by_token.return_value = stored
    response = client.post(
        "/api/v1/authorize/token",
        data={"grant_type": "refresh_token", "refresh_token": "stolen-refresh-token"},
        headers={"x-amzn-mtls-clientcert-leaf": client_certificate(roles=[TEST_ROLE])},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert "stolen-refresh-token" not in response.text
    assert len(responses.calls) == 0


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@patch("api.main.messaging.send_revocation_message")
@patch("api.main.permissions.revoke_permission")
@patch("api.hydra.get_session")
@responses.activate
def test_revoke_token_success(
    mock_get_session, mock_revoke_permission, mock_send_message
):
    """Test a successful token revocation."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    mock_session = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_session.post.return_value = mock_response
    mock_get_session.return_value = mock_session
    mock_revoke_permission.return_value = MagicMock()
    mock_send_message.return_value = True

    response = client.post(
        "/api/v1/authorize/revoke",
        data={
            "token": MOCK_REFRESH_TOKEN,
            "token_type_hint": "refresh_token",
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 200
    json_response = response.json()
    assert json_response["status"] == "success"
    assert json_response["message"] == "Token revoked"
    mock_revoke_permission.assert_called_once_with(MOCK_REFRESH_TOKEN, CLIENT_ID)
    mock_session.post.assert_called_once_with(
        f"{FakeConf().ORY_URL}/oauth2/revoke",
        data={"token": MOCK_REFRESH_TOKEN, "token_type_hint": "refresh_token"},
        timeout=10.0,
    )


@patch("api.main.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@patch("api.main.messaging.send_revocation_message")
@patch("api.permissions.write_permission")
@patch("api.permissions.get_permission_by_token")
@responses.activate
def test_revoke_token_refuses_another_client(
    mock_get_permission_by_token, mock_write_permission, mock_send_message
):
    """
    A leaked refresh token cannot be used by another Member to revoke the
    Permission. Nothing is revoked at Hydra and no message is sent.
    """
    mock_get_permission_by_token.return_value = stored_permission(
        client="https://directory.core.ib1.org/application/other"
    )

    response = client.post(
        "/api/v1/authorize/revoke",
        data={"token": "leaked-refresh-token", "token_type_hint": "refresh_token"},
        headers={
            "x-amzn-mtls-clientcert-leaf": client_certificate(roles=[TEST_ROLE])
        },
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_grant",
        "error_description": "Permission not found",
    }
    assert len(responses.calls) == 0
    mock_write_permission.assert_not_called()
    mock_send_message.assert_not_called()


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.main.permissions.revoke_permission")
def test_revoke_token_permission_error(mock_revoke_permission):
    """Test token revocation when permission revocation fails."""
    from api.exceptions import PermissionRevocationError

    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    mock_revoke_permission.side_effect = PermissionRevocationError(
        "Permission not found"
    )

    response = client.post(
        "/api/v1/authorize/revoke",
        data={
            "token": MOCK_REFRESH_TOKEN,
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert "Permission not found" in response.json()["error_description"]


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@patch("api.main.permissions.revoke_permission")
@patch("api.hydra.get_session")
def test_revoke_token_hydra_caller_error(mock_get_session, mock_revoke_permission):
    """A caller-actionable revocation error keeps Hydra's own wording."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    mock_session = MagicMock()
    mock_session.post.return_value = hydra_error(HYDRA_UNSUPPORTED_TOKEN_TYPE, 400)
    mock_get_session.return_value = mock_session
    mock_revoke_permission.return_value = {}

    response = client.post(
        "/api/v1/authorize/revoke",
        data={
            "token": MOCK_REFRESH_TOKEN,
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "unsupported_token_type"
    assert "does not support the revocation" in body["error_description"]


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@patch("api.main.permissions.revoke_permission")
@patch("api.hydra.get_session")
def test_revoke_token_hydra_rejects_our_credentials(
    mock_get_session, mock_revoke_permission
):
    """invalid_client is our misconfiguration, so nothing upstream is forwarded."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    mock_session = MagicMock()
    mock_session.post.return_value = hydra_error(HYDRA_INVALID_CLIENT, 401)
    mock_get_session.return_value = mock_session
    mock_revoke_permission.return_value = {}

    response = client.post(
        "/api/v1/authorize/revoke",
        data={
            "token": MOCK_REFRESH_TOKEN,
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 502
    assert response.json()["error"] == "server_error"
    assert "sql: no rows" not in response.text
    assert "does not exist" not in response.text


@patch("api.main.store.get_callback")
def test_callback_redirects_to_stored_url(mock_get_callback):
    """Test callback endpoint redirects to the original stored URL."""
    mock_get_callback.return_value = {
        "redirect_uri": "https://mobile.example.com/cb",
        "client_state": "WFqUWTVvX49tM",
    }
    response = client.get(
        "/api/v1/callback",
        params={"code": "auth_code_123", "state": "hydra_state", "scope": "profile"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = urlparse(response.headers["Location"])
    assert location.netloc == "mobile.example.com"
    assert location.path == "/cb"
    assert parse_qs(location.query) == {
        "code": ["auth_code_123"],
        "state": ["WFqUWTVvX49tM"],
        "scope": ["profile"],
        "iss": [conf.ISSUER_URL],
    }
    mock_get_callback.assert_called_once_with("hydra_state")


@patch("api.main.store.get_callback")
def test_callback_without_client_state(mock_get_callback):
    """Our state is not leaked to a client that sent none"""
    mock_get_callback.return_value = {
        "redirect_uri": "https://mobile.example.com/cb",
        "client_state": None,
    }
    response = client.get(
        "/api/v1/callback",
        params={"code": "auth_code_123", "state": "hydra_state"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = urlparse(response.headers["Location"])
    assert parse_qs(location.query) == {
        "code": ["auth_code_123"],
        "iss": [conf.ISSUER_URL],
    }


@patch("api.main.store.get_callback")
def test_callback_error_carries_iss(mock_get_callback):
    """An error response carries iss too (RFC 9207 section 2)"""
    mock_get_callback.return_value = {
        "redirect_uri": "https://mobile.example.com/cb",
        "client_state": "WFqUWTVvX49tM",
    }
    response = client.get(
        "/api/v1/callback",
        params={"error": "access_denied", "state": "hydra_state"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = urlparse(response.headers["Location"])
    assert parse_qs(location.query) == {
        "error": ["access_denied"],
        "state": ["WFqUWTVvX49tM"],
        "iss": [conf.ISSUER_URL],
    }


@patch("api.main.store.get_callback")
def test_callback_replaces_upstream_iss(mock_get_callback):
    """An iss from Hydra names Hydra, not us, so the client never sees it"""
    mock_get_callback.return_value = {
        "redirect_uri": "https://mobile.example.com/cb",
        "client_state": None,
    }
    response = client.get(
        "/api/v1/callback",
        params={
            "code": "auth_code_123",
            "state": "hydra_state",
            "iss": "https://example.projects.oryapis.com",
        },
        follow_redirects=False,
    )
    location = urlparse(response.headers["Location"])
    assert parse_qs(location.query)["iss"] == [conf.ISSUER_URL]


@patch("api.main.store.get_callback")
def test_callback_iss_matches_discovery(mock_get_callback):
    """RFC 9207 requires iss to equal the issuer in our metadata exactly"""
    mock_get_callback.return_value = {
        "redirect_uri": "https://mobile.example.com/cb",
        "client_state": None,
    }
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["authorization_response_iss_parameter_supported"] is True
    response = client.get(
        "/api/v1/callback",
        params={"code": "auth_code_123", "state": "hydra_state"},
        follow_redirects=False,
    )
    location = urlparse(response.headers["Location"])
    assert parse_qs(location.query)["iss"] == [metadata["issuer"]]


def test_callback_missing_state():
    """Test callback endpoint returns 400 when state is missing."""
    response = client.get(
        "/api/v1/callback",
        params={"code": "auth_code_123"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert "Missing state" in response.json()["error_description"]


@patch("api.main.store.get_callback")
def test_callback_expired_state(mock_get_callback):
    """Test callback endpoint returns 400 when state has expired."""
    mock_get_callback.return_value = None
    response = client.get(
        "/api/v1/callback",
        params={"code": "auth_code_123", "state": "expired_state"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert "not found or expired" in response.json()["error_description"]


def test_pushed_authorization_request_malformed_certificate():
    """PAR rejects an unparseable client certificate with 401."""
    response = client.post(
        "/api/v1/par",
        data={
            "client_id": CLIENT_ID,
            "redirect_uri": "https://mobile.example.com/cb",
            "code_challenge": "W78hCS0q72DfIHa...kgZkEJuAFaT4",
            "scope": "profile",
            "response_type": "code",
        },
        headers={"x-amzn-mtls-clientcert-leaf": "not-a-certificate"},
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert response.json()["error_description"] == "Invalid certificate string"


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
def test_token_wrong_role():
    """The token endpoint rejects a certificate without the provider role with 401."""
    cert_urlencoded = client_certificate(roles=[f"{SCHEME_URL}/role/some-other-role"])

    response = client.post(
        "/api/v1/authorize/token",
        data={
            "grant_type": "authorization_code",
            "code": "mock_code",
            "code_verifier": "mock_verifier",
            "redirect_uri": "https://mobile.example.com/cb",
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert "does not include role" in response.json()["error_description"]


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
def test_token_certificate_without_roles():
    """The token endpoint rejects a certificate with no role extension with 401."""
    cert_urlencoded = client_certificate()

    response = client.post(
        "/api/v1/authorize/token",
        data={
            "grant_type": "authorization_code",
            "code": "mock_code",
            "code_verifier": "mock_verifier",
            "redirect_uri": "https://mobile.example.com/cb",
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert "does not include role information" in response.json()["error_description"]


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.permissions.get_permission_by_token")
def test_revoke_token_does_not_echo_the_token(mock_get_permission_by_token):
    """An unknown token is not echoed back in the revocation error response."""
    mock_get_permission_by_token.return_value = None
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])

    response = client.post(
        "/api/v1/authorize/revoke",
        data={"token": MOCK_REFRESH_TOKEN},
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 400
    assert response.json()["error_description"] == "Permission not found"
    assert MOCK_REFRESH_TOKEN not in response.text


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.main.permissions.get_permission_by_token")
def test_permissions_does_not_echo_the_token(mock_get_permission_by_token):
    """An unknown token is not echoed back in the permissions error response."""
    mock_get_permission_by_token.return_value = None
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])

    response = client.post(
        "/api/v1/permissions",
        data={"token": MOCK_REFRESH_TOKEN},
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 404
    assert MOCK_REFRESH_TOKEN not in response.text


def test_default_issuer_is_the_host_without_client_certificates():
    """
    The deployed defaults, which local development overrides to one host. The
    issuer identifier must be the host a browser and a plain HTTP client can
    reach, not the mTLS host.
    """
    import importlib

    with patch.dict(os.environ, {}, clear=True):
        defaults = importlib.reload(conf)
        issuer, mtls = defaults.ISSUER_URL, defaults.MTLS_URL
    importlib.reload(conf)  # restore the values the rest of the suite runs with

    assert issuer == "https://perseus-demo-authentication.ib1.org"
    assert mtls == "https://mtls.perseus-demo-authentication.ib1.org"


# Local development serves both hosts from one nginx, so the metadata tests
# pin two distinct hosts to tell the endpoints apart.
ISSUER_HOST = "https://issuer.example.org"
MTLS_HOST = "https://mtls.example.org"


@patch.object(conf, "MTLS_URL", MTLS_HOST)
@patch.object(conf, "ISSUER_URL", ISSUER_HOST)
def test_metadata_is_published_by_the_issuer_it_names():
    """
    RFC 8414 section 3.3: the issuer in the document must be the identifier the
    document is published under. That host takes no client certificate, so any
    client can read the metadata and a browser can reach the authorization
    endpoint. The endpoints that need a client certificate live on the mTLS
    host, which the issuer identifier does not have to be.
    """
    metadata = client.get("/.well-known/oauth-authorization-server").json()

    assert metadata["issuer"] == ISSUER_HOST
    for field in ("authorization_endpoint", "jwks_uri"):
        assert metadata[field].startswith(ISSUER_HOST), field
    for field in (
        "pushed_authorization_request_endpoint",
        "token_endpoint",
        "revocation_endpoint",
        "ib1_permission_endpoint",
    ):
        assert metadata[field].startswith(MTLS_HOST), field


@patch.object(conf, "MTLS_URL", MTLS_HOST)
@patch.object(conf, "ISSUER_URL", ISSUER_HOST)
def test_metadata_names_the_permission_endpoint_as_the_specification_does():
    """
    Permission Records 1.0: "A client discovers the URL of the Permission
    endpoint from the ib1_permission_endpoint field in the OAuth Issuer's
    Authorization Server Metadata."
    """
    metadata = client.get("/.well-known/oauth-authorization-server").json()

    assert metadata["ib1_permission_endpoint"] == f"{MTLS_HOST}/api/v1/permissions"
    assert "permissions_endpoint" not in metadata


def test_metadata_states_how_to_authenticate_at_the_revocation_endpoint():
    """
    RFC 8414 defaults an unstated revocation_endpoint_auth_methods_supported to
    client_secret_basic, which this server does not accept.
    """
    metadata = client.get("/.well-known/oauth-authorization-server").json()

    assert metadata["revocation_endpoint_auth_methods_supported"] == ["tls_client_auth"]


@patch.object(conf, "MTLS_URL", MTLS_HOST)
@patch.object(conf, "ISSUER_URL", ISSUER_HOST)
def test_metadata_aliases_repeat_the_endpoints_exactly():
    """
    The IB1 OAuth profile: "Any *_endpoint value must be repeated exactly
    within the mtls_endpoint_aliases property so the aliased and unaliased
    values are equal."
    """
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    aliases = metadata["mtls_endpoint_aliases"]

    assert aliases
    for field, value in aliases.items():
        assert metadata[field] == value, field


@patch("api.main.conf", FakeConf())
@patch("api.main.permissions.get_permission_by_token")
def test_permissions_returns_the_record_to_its_client(mock_get_permission_by_token):
    stored = stored_permission(client=CLIENT_ID)
    mock_get_permission_by_token.return_value = stored

    response = client.post(
        "/api/v1/permissions",
        data={"token": "current-refresh-token"},
        headers={
            "x-amzn-mtls-clientcert-leaf": client_certificate(roles=[TEST_ROLE])
        },
    )

    assert response.status_code == 200
    assert response.json()["permissions"]["evidenceId"] == stored.evidenceId


@pytest.mark.parametrize("revoked", [None, datetime.datetime.now(datetime.timezone.utc)])
@patch("api.main.conf", FakeConf())
@patch("api.main.permissions.get_permission_by_token")
def test_permissions_hides_another_clients_record(mock_get_permission_by_token, revoked):
    """
    A token issued to another Application gets the same answer as an unknown
    one, so the caller cannot tell whether it exists
    """
    mock_get_permission_by_token.return_value = stored_permission(
        client="https://directory.core.ib1.org/application/other", revoked=revoked
    )

    response = client.post(
        "/api/v1/permissions",
        data={"token": "leaked-refresh-token"},
        headers={
            "x-amzn-mtls-clientcert-leaf": client_certificate(roles=[TEST_ROLE])
        },
    )

    assert response.status_code == 404
    assert response.json()["error_description"] == "No permissions found for token"
    assert "application/other" not in response.text
    assert "leaked-refresh-token" not in response.text


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@responses.activate
def test_token_hydra_caller_error():
    """A caller-actionable token error keeps Hydra's description and hint."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        json=HYDRA_INVALID_GRANT,
        status=400,
    )

    response = client.post(
        "/api/v1/authorize/token",
        data=TOKEN_REQUEST_DATA,
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "invalid_grant"
    assert "authorization grant" in body["error_description"]
    assert body["error_hint"] == HYDRA_INVALID_GRANT["error_hint"]
    assert "status_code" not in body


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@responses.activate
def test_token_hydra_rejects_our_credentials():
    """Hydra refusing our client credentials is not the caller's fault."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        json=HYDRA_INVALID_CLIENT,
        status=401,
    )

    response = client.post(
        "/api/v1/authorize/token",
        data=TOKEN_REQUEST_DATA,
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 502
    assert response.json()["error"] == "server_error"
    assert "sql: no rows" not in response.text
    assert "does not exist" not in response.text


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@responses.activate
def test_token_hydra_unparseable_body():
    """An HTML page from a proxy in front of Ory is dropped, not forwarded."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        body="<html><title>502 Bad Gateway</title></html>",
        status=502,
    )

    response = client.post(
        "/api/v1/authorize/token",
        data=TOKEN_REQUEST_DATA,
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 502
    assert response.json()["error"] == "server_error"
    assert "Bad Gateway" not in response.text


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@responses.activate
def test_token_hydra_timeout():
    """A timeout is a 504, not the unhandled 500 it used to be."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        body=requests.exceptions.ConnectTimeout(),
    )

    response = client.post(
        "/api/v1/authorize/token",
        data=TOKEN_REQUEST_DATA,
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 504
    assert response.json()["error"] == "server_error"


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@responses.activate
def test_token_hydra_unreachable():
    """A connection failure is a 502, not the unhandled 500 it used to be."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        body=requests.exceptions.ConnectionError(),
    )

    response = client.post(
        "/api/v1/authorize/token",
        data=TOKEN_REQUEST_DATA,
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 502
    assert response.json()["error"] == "server_error"


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@patch("api.auth.decode_with_jwks")
@patch("api.main.permissions.store_permission")
@responses.activate
def test_token_success_does_not_log_credentials(
    mock_store_permission, mock_decode_with_jwks, mock_auth, log_lines
):
    """The tokens Hydra issues must not reach the logs."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    mock_decode_with_jwks.return_value = {
        "client_id": CLIENT_ID,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "sub": "mock_user",
        "iss": FakeConf().ISSUER_URL,
        "scp": ["https://directory.ib1.org/roles/test"],
        "ext": {},
    }
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        json={"access_token": MOCK_TOKEN, "refresh_token": MOCK_REFRESH_TOKEN},
        status=200,
    )

    response = client.post(
        "/api/v1/authorize/token",
        data=TOKEN_REQUEST_DATA,
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 200
    logged = "\n".join(log_lines)
    assert MOCK_TOKEN not in logged
    assert MOCK_REFRESH_TOKEN not in logged
    # A reference is logged instead, so a support request can still be traced
    assert "Issued token for" in logged


def test_tracebacks_do_not_carry_frame_locals():
    """
    An unhandled exception must not put credentials in the logs.

    loguru defaults `diagnose` to True, which annotates every frame of a
    traceback with its local variables. In the token endpoint those locals hold
    the access and refresh tokens Hydra just issued, and in the resource app
    they hold the signing key, so any unhandled exception leaked them.

    This drives the ExceptionFormatter belonging to the handler configured in
    api/logger.py. Adding a test sink would not do, it would carry its own
    `diagnose` setting and prove nothing about the one that runs in production.
    """
    secret = "eyJhbGciOiJSUzI1NiIs-ACCESS-TOKEN-MUST-NOT-BE-LOGGED"

    def fails_holding_a_token(access_token):
        raise RuntimeError("storage is down")

    try:
        fails_holding_a_token(secret)
    except RuntimeError:
        handler = list(get_logger()._core.handlers.values())[0]
        formatted = "".join(
            handler._exception_formatter.format_exception(*sys.exc_info())
        )

    assert secret not in formatted
    # The traceback itself is still there, only the values are gone
    assert "fails_holding_a_token" in formatted
    assert "storage is down" in formatted


# Starlette re-raises unhandled exceptions in tests unless this is off, which
# would bypass the catch-all handler we want to exercise
error_client = TestClient(app, raise_server_exceptions=False)


def test_validation_error_uses_the_oauth_shape():
    """A missing form field is invalid_request, not Pydantic's 422 list."""
    cert_urlencoded = client_certificate()

    response = client.post(
        "/api/v1/par",
        data={"scope": "profile"},
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "invalid_request"
    # The failing parameters are named, so the Pydantic detail is not missed
    assert "response_type" in body["error_description"]
    assert "redirect_uri" in body["error_description"]
    assert "code_challenge" in body["error_description"]
    assert "detail" not in body


@patch("api.main.store.get_request")
def test_unhandled_error_is_reportable(mock_get_request):
    """An infrastructure failure carries an identifier the caller can quote."""
    mock_get_request.side_effect = RuntimeError("redis is down")

    response = error_client.get(
        "/api/v1/authorize",
        params={"request_uri": "urn:ietf:params:oauth:request_uri:abc"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    body = response.json()
    assert body["error"] == "server_error"
    assert len(body["correlation_id"]) == 12
    # Nothing about the underlying failure reaches the caller
    assert "redis" not in response.text.lower()


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.hydra.conf", FakeConf())
@responses.activate
def test_server_side_oauth_error_is_reportable():
    """A 502 is correlatable too, not only an unhandled exception."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    responses.add(
        responses.POST,
        f"{FakeConf().ORY_URL}/oauth2/token",
        json=HYDRA_INVALID_CLIENT,
        status=401,
    )

    response = client.post(
        "/api/v1/authorize/token",
        data=TOKEN_REQUEST_DATA,
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 502
    assert len(response.json()["correlation_id"]) == 12


def test_caller_error_has_no_correlation_id():
    """A 4xx is the caller's to fix, so there is nothing to report to us."""
    response = client.get(
        "/api/v1/callback",
        params={"code": "auth_code_123"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "correlation_id" not in response.json()


@patch("api.store.redis_connection")
def test_callback_store_round_trip(mock_redis_connection):
    """The client's state survives being stored alongside the callback URL"""
    from api import store

    saved = {}
    mock_redis = MagicMock()
    mock_redis.set.side_effect = saved.__setitem__
    mock_redis.get.side_effect = saved.get
    mock_redis_connection.return_value = mock_redis

    store.store_callback("our_state", "https://mobile.example.com/cb", "WFqUWTVvX49tM")
    assert store.get_callback("our_state") == {
        "redirect_uri": "https://mobile.example.com/cb",
        "client_state": "WFqUWTVvX49tM",
    }
    assert store.get_callback("unknown_state") is None


def test_openapi_servers_name_the_hosts_that_serve_each_path():
    """
    This API spans both hosts: a browser reaches the authorization endpoint on
    the public host, and the rest require a client certificate. Every server
    URL must be absolute, or a client resolves it against the document's own
    URL.
    """
    schema = client.get("/openapi.json").json()

    assert schema["servers"] == [
        {"url": conf.ISSUER_URL, "description": "No client certificate required"}
    ]
    for path in (
        "/api/v1/par",
        "/api/v1/authorize/token",
        "/api/v1/authorize/revoke",
        "/api/v1/permissions",
    ):
        assert schema["paths"][path]["servers"] == [
            {"url": conf.MTLS_URL, "description": "Requires a client certificate"}
        ], path
    assert "servers" not in schema["paths"]["/api/v1/authorize"]
    urls = [server["url"] for server in schema["servers"]]
    urls += [
        server["url"]
        for path in schema["paths"].values()
        for server in path.get("servers", [])
    ]
    for url in urls:
        assert url.startswith("https://"), url
