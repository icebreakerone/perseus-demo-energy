import os
from unittest.mock import patch, MagicMock
import jwt
import responses
from fastapi.testclient import TestClient
from api.main import app, conf
from tests import client_certificate, CLIENT_ID

client = TestClient(app)
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


class FakeConf:
    def __init__(self) -> None:
        self.DIRNAME = conf.DIRNAME
        self.CERTS = conf.CERTS
        self.ISSUER_URL = os.environ.get(
            "ISSUER_URL", "https://perseus-demo-authentication.ib1.org"
        )
        self.OAUTH_CLIENT_SECRET = "123abc"
        self.OAUTH_URL = "https://test-oauth.io"
        self.OAUTH_CLIENT_ID = "abc-123"
        self.AUTHORIZATION_ENDPOINT = f"{self.OAUTH_URL}/oauth2/auth"
        self.TOKEN_ENDPOINT = f"{self.OAUTH_URL}/oauth2/token"
        self.REDIRECT_URI = "https://test-accounting.org/callback"
        self.REDIS_HOST = "redis"


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
            "state": "abc123",
            "response_type": "code",
        },
        headers={"x-amzn-mtls-clientcert": cert_urlencoded},
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
        "state": "abc123",
        "code_challenge": "123123123",
    }
    response = client.get(
        "/api/v1/authorize",
        params={
            "client_id": CLIENT_ID,
            "request_uri": "urn:ietf:params:oauth:request_uri:O38VUUUC1quZR59Fhx0TrTLZGX4",
        },
        headers={"x-amzn-mtls-clientcert": cert_urlencoded},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "Location" in response.headers


@patch("api.auth.get_pem")
@patch("api.main.conf", FakeConf())
@responses.activate
def test_token(mocked_auth_key):  # noqa
    cert_urlencoded = client_certificate(
        roles=["https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting"]
    )
    test_key = f"{ROOT_DIR}/fixtures/server-signing-private-key.pem"
    mocked_auth_key.return_value = test_key
    valid_response = {
        "aud": [],
        "client_id": CLIENT_ID,
        "exp": 1713344558,
        "ext": {},
        "iat": 1713340957,
        "iss": "https://oauth-originator.projects.oryapis.com",
        "jti": "ffaaa9f1-4b06-44f7-a812-cd347a179a28",
        "nbf": 1713340957,
        "scp": ["profile", "offline_access"],
        "sub": "subject-id",
    }
    with open(f"{ROOT_DIR}/fixtures/server-signing-private-key.pem", "rb") as f:
        private_key = f.read()
    token = jwt.encode(valid_response, private_key, algorithm="ES256")
    responses.post(
        f"{FakeConf().TOKEN_ENDPOINT}",
        json={
            "access_token": token,
            "id_token": "ID_TOKEN",
            "refresh_token": "REFRESH_TOKEN",
        },
    )
    response = client.post(
        "/api/v1/authorize/token",
        data={
            "code": "some-code",
            "redirect_uri": "https://mobile.example.com/cb",
            "client_id": 123456,
            "code_verifier": "abc123",
            "grant_type": "authorization_code",
        },
        headers={"x-amzn-mtls-clientcert": cert_urlencoded},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()
