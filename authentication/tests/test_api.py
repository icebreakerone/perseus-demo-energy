import os
from unittest.mock import patch, MagicMock

import pytest
import responses
from fastapi.testclient import TestClient

from api.main import app, conf
from api import auth
from tests import client_certificate, CLIENT_ID

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
        self.ORY_TOKEN_ENDPOINT = f"{self.ORY_URL}/oauth2/token"
        self.REDIRECT_URI = "https://test-accounting.org/callback"
        self.REDIS_HOST = "redis"


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
        "api.main.auth.create_enhanced_access_token", return_value=MOCK_ENHANCED_TOKEN
    ) as mock_auth:
        yield mock_auth


@pytest.fixture
def jwt_signing_jwks():
    return auth.create_jwks(f"{ROOT_DIR}/fixtures/server-signing-private-key.pem")


# Mock the redis server, as pushed_authorization_request() uses it
# @responses.activate
@patch("api.par.redis_connection")
def test_pushed_authorization_request(mock_redis_connection):
    cert_urlencoded = client_certificate()
    mock_redis = MagicMock()
    mock_redis.set.return_value = True
    mock_redis_connection.return_value = mock_redis
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
    cert_urlencoded = client_certificate(
        roles=["https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting"]
    )
    redirect = "http://anywhere.com"
    mock_get_request.return_value = {
        "client_id": CLIENT_ID,
        "redirect_uri": redirect,
        "scope": "profile",
        "code_challenge": "123123123",
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
@responses.activate
def test_token_success(mock_directory, mock_auth):
    """Test a successful token request."""
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
        headers={"x-amzn-mtls-clientcert-leaf": "mock_cert"},
    )

    assert response.status_code == 200
    json_response = response.json()
    assert json_response["access_token"] == MOCK_TOKEN
