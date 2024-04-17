import os
from unittest.mock import patch, MagicMock
import urllib.parse

import jwt
import responses
from fastapi.testclient import TestClient
from api.main import app, conf
from api.auth import get_key


client = TestClient(app)
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def client_certificate() -> str:
    with open(f"{ROOT_DIR}/fixtures/client-cert.pem") as f:
        certificate = f.read()
    encoded_certificate = urllib.parse.quote(certificate)
    return encoded_certificate


# Mock the redis server, as pushed_authorization_request() uses it
# @responses.activate
@patch("api.par.redis_connection")
def test_pushed_authorization_request(mock_redis_connection):
    mock_redis = MagicMock()
    mock_redis.set.return_value = True
    mock_redis_connection.return_value = mock_redis
    response = client.post(
        "/api/v1/par",
        data={
            "client_id": 123456,
            "redirect_uri": "https://mobile.example.com/cb",
            "code_challenge": "W78hCS0q72DfIHa...kgZkEJuAFaT4",
            "scope": "profile",
            "state": "abc123",
            "response_type": "code",
        },
        headers={"x-amzn-mtls-clientcert": client_certificate()},
    )

    assert response.status_code == 200
    print(response.json())
    assert "request_uri" in response.json()


@patch("api.par.get_request")
def test_authorization_code(mock_get_request):
    client_id = "aaaa-1111-2222"
    redirect = "http://anywhere.com"
    mock_get_request.return_value = {
        "client_id": client_id,
        "redirect_uri": redirect,
        "scope": "profile",
        "state": "abc123",
        "code_challenge": "123123123",
    }
    response = client.get(
        "/api/v1/authorize",
        params={
            "client_id": client_id,
            "request_uri": "urn:ietf:params:oauth:request_uri:O38VUUUC1quZR59Fhx0TrTLZGX4",
        },
        headers={"x-amzn-mtls-clientcert": "client-certificate"},
        follow_redirects=False,
    )
    print(response.status_code, response.text)
    assert response.status_code == 302
    assert "Location" in response.headers


@responses.activate
def test_token():
    client_id = "aaaa-1111-2222"
    valid_response = {
        "aud": [],
        "client_id": client_id,
        "exp": 1713344558,
        "ext": {},
        "iat": 1713340957,
        "iss": "https://oauth-originator.projects.oryapis.com",
        "jti": "ffaaa9f1-4b06-44f7-a812-cd347a179a28",
        "nbf": 1713340957,
        "scp": ["profile", "offline_access"],
        "sub": "subject-id",
    }
    private_key_path = get_key("key")
    with open(private_key_path, "rb") as f:
        private_key = f.read()
    token = jwt.encode(valid_response, private_key, algorithm="ES256")
    responses.post(
        f"{conf.TOKEN_ENDPOINT}",
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
        headers={"x-amzn-mtls-clientcert": client_certificate()},
    )
    print(response.text)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "id_token" in response.json()
    assert "refresh_token" in response.json()


def test_introspect():
    # todo
    pass


def test_login_for_access_token():
    # todo
    pass


def test_user_consent():
    # todo
    pass
