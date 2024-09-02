import pytest
import jwt
import time

from unittest.mock import patch, MagicMock
from tests import CLIENT_ID, client_certificate  # noqa
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

    cert_pem, private_key_pem, private_key, cert_thumbprint = (
        client_certificate()
    )  # noqa
    headers = {"alg": "RS256", "kid": "testkey"}
    payload = {
        "aud": CLIENT_ID,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()) - 3600,
        "active": True,
        "iss": "https://some-issuer.com",
        "cnf": {"x5t#S256": cert_thumbprint},
    }
    jwt_token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    # Mock the OpenID configuration to use our test JWKS endpoint
    mock_get_openid_config.return_value = {"jwks_uri": "https://mock_jwks_uri"}

    # Create a mock signing key to be returned by the JWK client
    mock_jwk_client_instance = MagicMock()
    mock_jwk_client_instance.get_signing_key.return_value.key = private_key.public_key()
    mock_jwk_client.return_value = mock_jwk_client_instance

    # Act
    result, headers = api.auth.check_token(cert_pem, jwt_token)

    # Assert
    assert result["aud"] == CLIENT_ID
    assert "x-fapi-interaction-id" in headers
