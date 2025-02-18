import jwt
import pytest
import json
from unittest.mock import patch
import time
import os

from botocore.exceptions import ClientError
from jwt.algorithms import ECAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from api.auth import (
    decode_with_jwks,
    create_jwks,
    create_enhanced_access_token,
    get_thumbprint,
)
from tempfile import NamedTemporaryFile
from api.exceptions import (
    AccessTokenDecodingError,
)

TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1(), default_backend())
TEST_PUBLIC_KEY = TEST_PRIVATE_KEY.public_key()
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))


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


@patch("api.keystores.get_boto3_client")
def test_create_jwks(mock_get_boto3_client):
    # write TEST_PRIVATE_KEY to a temp file
    mock_ssm_client = mock_get_boto3_client.return_value
    mock_ssm_client.exceptions.ParameterNotFound = ClientError
    mock_ssm_client.exceptions.ClientError = ClientError
    mock_ssm_client.get_parameter.side_effect = ClientError(
        {
            "Error": {
                "Code": "ParameterNotFound",
                "Message": "Parameter not found",
            }
        },
        "get_parameter",
    )
    with NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(
            TEST_PRIVATE_KEY.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        temp_file_path = temp_file.name
    result = create_jwks(temp_file_path)
    assert "keys" in result
    assert len(result["keys"]) == 1
    assert result["keys"][0]["kty"] == "EC"
    assert result["keys"][0]["crv"] == "P-256"
    assert result["keys"][0]["use"] == "sig"

    assert result["keys"][0]["kid"] == "1"


@patch("api.auth.decode_with_jwks")
@patch("api.auth.keystores.get_key")
def test_create_enhanced_access_token(mock_get_key, mock_decode_with_jwks):
    mock_decode_with_jwks.return_value = {
        "sub": "123",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()) - 10,
    }
    mock_private_key = TEST_PRIVATE_KEY
    mock_get_key.return_value = mock_private_key
    with open(f"{ROOT_DIR}/fixtures/test-client-cert.pem", "r") as f:
        test_certificate = f.read()
    enhanced_token = create_enhanced_access_token(
        {}, test_certificate, "https://mocked-oauth.com/.well-known/jwks.json"
    )

    decoded_enhanced_token = jwt.decode(
        enhanced_token, TEST_PUBLIC_KEY, algorithms=["ES256"]
    )
    assert "cnf" in decoded_enhanced_token
    assert "x5t#S256" in decoded_enhanced_token["cnf"]
    assert decoded_enhanced_token["cnf"]["x5t#S256"] == get_thumbprint(test_certificate)
