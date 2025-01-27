import datetime
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
import pytest
from fastapi.testclient import TestClient

from tests import client_certificate, ROOT_DIR  # noqa
from api.main import app
from api import conf

client = TestClient(app)


@pytest.fixture
def mock_check_token(mocker):
    return mocker.patch("api.main.auth.check_token")


@pytest.fixture
def mock_ib1_directory_load_key(mocker):
    return mocker.patch("api.provenance.load_key")


def get_private_key():
    with open(f"{ROOT_DIR}/fixtures/test-suite-key.pem") as f:
        return serialization.load_pem_private_key(
            f.read().encode(),
            password=None,
        )


@pytest.fixture
def api_consumption_url():
    from_date = datetime.date.today().isoformat()
    to_date = datetime.date.today().isoformat()
    return f"/datasources/anyid/anymeasure?from={from_date}&to={to_date}"


def test_consumption_no_token(api_consumption_url):
    response = client.get(api_consumption_url)
    assert response.status_code == 401


def test_consumption_bad_token(api_consumption_url):

    response = client.get(
        api_consumption_url,
        headers={"Authorization": "Bearer"},
    )
    assert response.status_code == 401


def test_consumption(
    monkeypatch, mock_ib1_directory_load_key, mock_check_token, api_consumption_url
):  # noqa
    """
    If introspection is successful, return data and 200
    """
    monkeypatch.setattr(
        conf, "ROOT_CA_CERTIFICATE", f"{ROOT_DIR}/fixtures/test-suite-cert.pem"
    )
    monkeypatch.setattr(
        conf, "SIGNING_BUNDLE", f"{ROOT_DIR}/fixtures/test-suite-cert.pem"
    )
    mock_check_token.return_value = (
        {"sub": "account123"},
        {"x-fapi-interaction-id": "123"},
    )
    mock_ib1_directory_load_key.return_value = get_private_key()
    pem, _, _, _ = client_certificate(
        roles=["https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting"],
        application="https://directory.ib1.org/application/123456",
    )
    response = client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert": quote(pem),
        },
    )
    assert response.status_code == 200
