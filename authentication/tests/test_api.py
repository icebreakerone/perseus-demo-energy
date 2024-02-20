import datetime

import responses
import pytest
from fastapi.testclient import TestClient
from api.main import app, conf
from api import authentication, examples

client = TestClient(app)


@pytest.fixture
def mock_token(mocker):
    access_token_expires = datetime.timedelta(
        minutes=authentication.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    access_token = authentication.create_access_token(
        data={"sub": "platform_user"}, expires_delta=access_token_expires
    )
    return access_token


@responses.activate
def test_pushed_authorization_request():
    responses.post(
        f"{conf.FAPI_API}/auth/par/",
        json={
            "response_content": '{"request_uri": "https://some-uri.com?ticket=1", "expires_in": 3600}'
        },
    )
    response = client.post(
        "/api/v1/par",
        json={
            "client_id": 123456,
            "redirect_uri": "https://mobile.example.com/cb",
            "code_challenge": "W78hCS0q72DfIHa...kgZkEJuAFaT4",
            "code_challenge_method": "S256",
            "response_type": "code",
        },
        headers={"x_amzn_mtls_clientcert": "client-certificate"},
    )
    assert response.status_code == 200
    assert "request_uri" in response.json()


@responses.activate
def test_authorization_code():
    responses.post(
        f"{conf.FAPI_API}/auth/authorization",
        json={"ticket": "abc123"},
    )
    response = client.post(
        "/api/v1/authorize",
        json={"request_uri": "test-uri", "client_id": 123456},
        headers={"x-amzn-mtls-clientcert": "client-certificate"},
    )
    assert response.status_code == 200
    assert "ticket" in response.json()


@responses.activate
def test_issue(mock_token):
    # Use responses library to mock the response from the FAPI API
    responses.post(
        f"{conf.FAPI_API}/auth/authorization/issue",
        json=examples.ISSUE_RESPONSE,
    )
    response = client.post(
        "/api/v1/authorize/issue",
        json={"ticket": "test-ticket"},
        headers={"Authorization": f"Bearer {mock_token}"},
    )
    assert response.status_code == 200


@responses.activate
def test_token():
    responses.post(
        f"{conf.FAPI_API}/auth/token/",
        json={
            "access_token": "ABC123",
            "id_token": "ID_TOKEN",
            "refresh_token": "REFRESH_TOKEN",
        },
    )
    response = client.post(
        "/api/v1/authorize/token",
        json={
            "parameters": "grant_type=authorization_code&redirect_uri=https://client.example.org/cb/example.com&code=DxiKC0cOc_46nzVjgr41RWBQtMDrAvc0BUbMJ_v7I70",
            "client_id": 123456,
        },
        headers={"x-amzn-mtls-clientcert": "client-certificate"},
    )
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
