import pytest
import jwt
import time

from unittest.mock import patch
from tests import CLIENT_ID, CATALOG_ENTRY_URL, client_certificate  # noqa
import api.auth


@pytest.fixture
def mock_parse_request(mocker):
    return mocker.patch("api.auth.parse_cert")


@pytest.fixture
def mock_check_token(mocker):
    return mocker.patch("api.auth.check_token")


@patch("api.auth.get_openid_configuration")
@patch("api.auth.jwt.PyJWKClient")
def test_check_token_integration(mock_jwk_client, mock_get_openid_config):  # noqa
    aud = "https://perseus-demo-energy.ib1.org/data-service/consumption"
    cert_pem, private_key_pem, private_key, cert_thumbprint = client_certificate(
        roles=["https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting"],
        application=CLIENT_ID,
    )  # noqa
    headers = {"alg": "RS256", "kid": "testkey"}
    payload = {
        "client_id": CLIENT_ID,
        "aud": CATALOG_ENTRY_URL,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()) - 3600,
        "active": True,
        "sub": "account123",
        "iss": "https://some-issuer.com",
        "cnf": {"x5t#S256": cert_thumbprint},
    }
    jwt_token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    # Act
    result, headers = api.auth.check_token(cert_pem, jwt_token, CATALOG_ENTRY_URL)

    # Assert
    print(result)
    assert result["aud"] == aud
    assert result["client_id"] == CLIENT_ID
    assert "x-fapi-interaction-id" in headers
