import os
from unittest.mock import patch, MagicMock
import time

import pytest
import responses
from fastapi.testclient import TestClient

from api.main import app, conf
from api import auth
from api.logger import get_logger
from tests import client_certificate, CLIENT_ID, TEST_ROLE

logger = get_logger()
client = TestClient(app)
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MOCK_TOKEN = "mock_enhanced_access_token"
MOCK_ENHANCED_TOKEN = "mock_enhanced_access_token"
MOCK_REFRESH_TOKEN = "mock_refresh_token"
MOCK_CERT = "mock_client_cert"


class FakeConf:
    def __init__(self) -> None:
        self.DIRNAME = conf.DIRNAME
        self.ISSUER_URL = os.environ.get(
            "ISSUER_URL", "https://perseus-demo-authentication.ib1.org"
        )
        self.ORY_CLIENT_SECRET = "123abc"
        self.ORY_URL = "https://test-oauth.io"
        self.ORY_CLIENT_ID = "abc-123"
        self.JWKS_URL = f"{self.ORY_URL}/.well-known/jwks.json"
        self.JWT_SIGNING_KEY = f"{ROOT_DIR}/fixtures/server-signing-private-key.pem"
        self.ORY_TOKEN_ENDPOINT = f"{self.ORY_URL}/oauth2/token"
        self.REDIRECT_URI = "https://test-accounting.org/callback"
        self.REDIS_HOST = "redis"
        self.PROVIDER_ROLE = TEST_ROLE


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
# @responses.activate
@patch("api.par.redis_connection")
@patch("api.main.auth.create_state_token")
def test_pushed_authorization_request(mock_create_state_token, mock_redis_connection):
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
        },
        headers={"x-amzn-mtls-clientcert-leaf": cert_urlencoded},
    )

    assert response.status_code == 201
    assert "request_uri" in response.json()


@patch("api.par.get_request")
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


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.auth.decode_with_jwks")
@patch("api.main.permissions")
@responses.activate
def test_token_success(mock_permissions, mock_decode_with_jwks, mock_auth):
    """Test a successful token request."""
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


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.main.messaging.send_revocation_message")
@patch("api.main.permissions.revoke_permission")
@patch("api.main.auth.get_session")
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
    mock_revoke_permission.assert_called_once_with(MOCK_REFRESH_TOKEN)
    mock_session.post.assert_called_once_with(
        f"{FakeConf().ORY_URL}/oauth2/revoke",
        data={"token": MOCK_REFRESH_TOKEN, "token_type_hint": "refresh_token"},
    )


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
    assert "Permission not found" in response.json()["detail"]


@patch("api.main.conf", FakeConf())
@patch("api.auth.conf", FakeConf())
@patch("api.main.permissions.revoke_permission")
@patch("api.main.auth.get_session")
@responses.activate
def test_revoke_token_hydra_error(mock_get_session, mock_revoke_permission):
    """Test token revocation when Hydra returns an error."""
    cert_urlencoded = client_certificate(roles=[TEST_ROLE])
    mock_session = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Invalid token"
    mock_session.post.return_value = mock_response
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
    assert "Invalid token" in response.json()["detail"]
