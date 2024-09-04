from urllib.parse import quote
import pytest
from fastapi.testclient import TestClient
from tests import client_certificate  # noqa
from api.main import app

client = TestClient(app)


@pytest.fixture
def mock_check_token(mocker):
    return mocker.patch("api.main.auth.check_token")


def test_consumption_no_token():
    response = client.get("/api/v1/consumption")
    assert response.status_code == 401


def test_consumption_bad_token():
    response = client.get("/api/v1/consumption", headers={"Authorization": "Bearer"})
    assert response.status_code == 401


def test_consumption(mock_check_token):  # noqa
    """
    If introspection is successful, return data and 200
    """
    mock_check_token.return_value = ({}, {})
    pem, _, _, _ = client_certificate(
        roles=["https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting"]
    )
    response = client.get(
        "/api/v1/consumption",
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert": quote(pem),
        },
    )
    assert response.status_code == 200
