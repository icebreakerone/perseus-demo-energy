import pytest
import jwt
from jwt.algorithms import RSAAlgorithm
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import api.conf
from api.auth import decode_with_jwks  # Replace 'api.auth' with your actual module name


@pytest.fixture
def rsa_key_pair():
    """Generate an RSA key pair for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Export keys in JWK format as dictionaries
    private_jwk = json.loads(RSAAlgorithm.to_jwk(private_key))
    public_jwk = json.loads(RSAAlgorithm.to_jwk(public_key))

    return private_key, public_key, private_jwk, public_jwk


@pytest.fixture
def mock_jwks_response(rsa_key_pair):
    """Fixture for mocking a JWKS response."""
    _, public_key, _, public_jwk = rsa_key_pair
    jwks_key = {
        "kid": "test-key-id",
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        **public_jwk,
    }
    return {"keys": [jwks_key]}


@patch("api.auth.requests.get")
def test_decode_with_jwks_valid_token(mock_get, mock_jwks_response, rsa_key_pair):
    """Test decoding a valid token."""
    private_key, _, _, _ = rsa_key_pair

    # Mock the JWKS endpoint response
    mock_get.return_value = MagicMock(status_code=200, json=lambda: mock_jwks_response)

    # Create a token signed with the private key
    token = jwt.encode(
        {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022,
            "iss": api.conf.OAUTH_URL,
        },
        key=private_key,
        algorithm="RS256",
        headers={"kid": "test-key-id"},
    )

    # Call the function
    url = api.conf.OAUTH_URL
    decoded_token = decode_with_jwks(token, url)

    # Assertions
    assert decoded_token["sub"] == "1234567890"
    assert decoded_token["name"] == "John Doe"


@patch("api.auth.requests.get")
def test_decode_with_jwks_invalid_kid(mock_get, rsa_key_pair):
    """Test decoding a token with an invalid `kid`."""
    private_key, public_key, _, _ = rsa_key_pair

    # Mock the JWKS endpoint response with an unrelated key ID
    mock_get.return_value = MagicMock(
        status_code=200,
        json=lambda: {
            "keys": [
                {"kid": "another-key-id", **json.loads(RSAAlgorithm.to_jwk(public_key))}
            ]
        },
    )

    # Create a token
    token = jwt.encode(
        {"sub": "1234567890"},
        key=private_key,
        algorithm="RS256",
        headers={"kid": "test-key-id"},
    )

    # Call the function and assert it raises a ValueError
    url = api.conf.OAUTH_URL
    with pytest.raises(
        api.exceptions.AccessTokenDecodingError,
    ):
        decode_with_jwks(token, url)


@patch("api.auth.requests.get")
def test_decode_with_jwks_expired_token(mock_get, mock_jwks_response, rsa_key_pair):
    """Test decoding an expired token."""
    private_key, _, _, _ = rsa_key_pair

    # Mock the JWKS endpoint response
    mock_get.return_value = MagicMock(status_code=200, json=lambda: mock_jwks_response)

    # Create an expired token
    expired_token = jwt.encode(
        {"sub": "1234567890", "exp": 0},  # Token is already expired
        key=private_key,
        algorithm="RS256",
        headers={"kid": "test-key-id"},
    )

    # Call the function and assert it raises an AccessTokenDecodingError
    url = api.conf.OAUTH_URL
    with pytest.raises(
        Exception, match="Token has expired!"
    ):  # Replace Exception with your custom exception
        decode_with_jwks(expired_token, url)
