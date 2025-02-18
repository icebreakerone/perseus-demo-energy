import jwt
import pytest
import json
from unittest.mock import patch
import time
import os

from jwt.algorithms import ECAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from api.auth import decode_with_jwks, check_token
from api.exceptions import (
    AccessTokenAudienceError,
    AccessTokenTimeError,
    AccessTokenDecodingError,
)

TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1(), default_backend())
TEST_PUBLIC_KEY = TEST_PRIVATE_KEY.public_key()
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MOCK_CERTIFICATE = "mocked-certificate"
MOCK_TOKEN = "mocked-token"


# Create a JWKS response with the EC public key
def create_mock_jwks(kid="test-key-id"):
    jwk = json.loads(ECAlgorithm.to_jwk(TEST_PUBLIC_KEY))
    jwk["kid"] = kid  # Add the Key ID to match the token header
    jwk["use"] = "sig"
    return {"keys": [jwk]}


@pytest.fixture
def mock_jwks():
    jwks_url = "https://mocked-jwks.com/.well-known/jwks.json"
    mock_response = json.dumps(create_mock_jwks()).encode()

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.read.return_value = (
            mock_response
        )
        yield jwks_url


@pytest.fixture
def mock_decoded_token():
    return {
        "client_id": "test-client-id",
        "exp": int(time.time()) + 3600,  # Token valid for 1 hour
        "iat": int(time.time()) - 10,  # Issued 10 seconds ago
    }


def test_decode_valid_token(mock_jwks):
    jwks_url = "https://mocked-jwks.com/.well-known/jwks.json"
    token = jwt.encode(
        {"sub": "123"},
        TEST_PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": "test-key-id"},
    )
    payload = decode_with_jwks(token, jwks_url)
    assert payload["sub"] == "123"


def test_invalid_signature(mock_jwks):
    wrong_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    token = jwt.encode(
        {"sub": "123"}, wrong_key, algorithm="ES256", headers={"kid": "test-key-id"}
    )

    with pytest.raises(AccessTokenDecodingError):
        decode_with_jwks(token, mock_jwks)


def test_missing_kid(mock_jwks):
    token = jwt.encode({"sub": "123"}, TEST_PRIVATE_KEY, algorithm="ES256")

    with pytest.raises(KeyError):
        decode_with_jwks(token, mock_jwks)


@patch("api.auth.decode_with_jwks")
@patch("api.auth.directory.parse_cert")
@patch("api.auth.directory.extensions.decode_application")
@patch("api.auth.check_certificate")
@patch("api.auth.conf")
def test_check_token_valid(
    mock_auth_conf,
    mock_check_certificate,
    mock_decode_application,
    mock_parse_cert,
    mock_decode_with_jwks,
    mock_decoded_token,
):
    mock_parse_cert.return_value = "mocked-parsed-cert"
    mock_decode_application.return_value = "test-client-id"
    mock_decode_with_jwks.return_value = mock_decoded_token
    mock_auth_conf.AUTHENTICATION_SERVER_CA = f"{ROOT_DIR}/fixtures/test-server-ca.pem"
    decoded, headers = check_token(MOCK_CERTIFICATE, MOCK_TOKEN)

    assert decoded == mock_decoded_token
    assert "Date" in headers
    assert "x-fapi-interaction-id" in headers

    mock_check_certificate.assert_called_once_with(
        "mocked-parsed-cert", mock_decoded_token
    )


@patch("api.auth.decode_with_jwks")
@patch("api.auth.directory.parse_cert")
@patch("api.auth.directory.extensions.decode_application")
@patch("api.auth.conf")
def test_check_token_invalid_client_id(
    mock_auth_conf,
    mock_decode_application,
    mock_parse_cert,
    mock_decode_with_jwks,
    mock_decoded_token,
):
    mock_auth_conf.AUTHENTICATION_SERVER_CA = f"{ROOT_DIR}/fixtures/test-server-ca.pem"
    mock_parse_cert.return_value = "mocked-parsed-cert"
    mock_decode_application.return_value = "wrong-client-id"  # Different from token
    mock_decode_with_jwks.return_value = mock_decoded_token

    with pytest.raises(AccessTokenAudienceError, match="Invalid Client ID"):
        check_token(MOCK_CERTIFICATE, MOCK_TOKEN)


@patch("api.auth.decode_with_jwks")
@patch("api.auth.directory.parse_cert")
@patch("api.auth.directory.extensions.decode_application")
@patch("api.auth.conf")
def test_check_token_expired_token(
    mock_auth_conf,
    mock_decode_application,
    mock_parse_cert,
    mock_decode_with_jwks,
    mock_decoded_token,
):
    mock_auth_conf.AUTHENTICATION_SERVER_CA = f"{ROOT_DIR}/fixtures/test-server-ca.pem"
    mock_parse_cert.return_value = "mocked-parsed-cert"
    mock_decode_application.return_value = "test-client-id"

    mock_decoded_token["exp"] = int(time.time()) - 10  # Token expired 10 sec ago
    mock_decode_with_jwks.return_value = mock_decoded_token

    with pytest.raises(AccessTokenTimeError, match="Token expired"):
        check_token(MOCK_CERTIFICATE, MOCK_TOKEN)


@patch("api.auth.decode_with_jwks")
@patch("api.auth.directory.parse_cert")
@patch("api.auth.directory.extensions.decode_application")
@patch("api.auth.conf")
def test_check_token_issued_in_future(
    mock_auth_conf,
    mock_decode_application,
    mock_parse_cert,
    mock_decode_with_jwks,
    mock_decoded_token,
):
    mock_auth_conf.AUTHENTICATION_SERVER_CA = f"{ROOT_DIR}/fixtures/test-server-ca.pem"
    mock_parse_cert.return_value = "mocked-parsed-cert"
    mock_decode_application.return_value = "test-client-id"

    mock_decoded_token["iat"] = int(time.time()) + 10  # Issued 10 sec in the future
    mock_decode_with_jwks.return_value = mock_decoded_token

    with pytest.raises(AccessTokenTimeError, match="Token issued in the future"):
        check_token(MOCK_CERTIFICATE, MOCK_TOKEN)
