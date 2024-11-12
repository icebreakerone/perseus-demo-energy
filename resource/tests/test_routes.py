import datetime
from urllib.parse import quote
import pytest
from fastapi.testclient import TestClient
from tests import client_certificate  # noqa
from api.main import app

client = TestClient(app)


@pytest.fixture
def mock_check_token(mocker):
    return mocker.patch("api.main.auth.check_token")


@pytest.fixture
def api_consumption_url():
    from_date = datetime.date.today().isoformat()
    to_date = datetime.date.today().isoformat()
    return f"/datasources/anyid/anymeasure?from_date={from_date}&to_date={to_date}"


def test_consumption_no_token(api_consumption_url):
    response = client.get(api_consumption_url)
    assert response.status_code == 401


def test_consumption_bad_token(api_consumption_url):

    response = client.get(
        api_consumption_url,
        headers={"Authorization": "Bearer"},
    )
    assert response.status_code == 401


def test_consumption(mock_check_token, api_consumption_url):  # noqa
    """
    If introspection is successful, return data and 200
    """
    mock_check_token.return_value = ({}, {})
    pem, _, _, _ = client_certificate(
        roles=["https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting"]
    )
    response = client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert": quote(pem),
        },
    )
    assert response.status_code == 200
