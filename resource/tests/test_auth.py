import pytest
import jwt
import time
import datetime
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from unittest.mock import patch, MagicMock

import api.auth

from tests import cert_response


@pytest.fixture
def mock_parse_request(mocker):
    return mocker.patch("api.auth.parse_cert")


@pytest.fixture
def mock_check_token(mocker):
    return mocker.patch("api.auth.check_token")


@pytest.fixture(scope="module")
def client_certificate():
    # Generate a self-signed certificate for testing
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mock_client_id"),
        ]
    )
    valid_from = datetime.datetime.utcnow()
    valid_until = valid_from + datetime.timedelta(hours=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Encode the certificate to PEM format
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # Calculate the thumbprint of the certificate
    cert_thumprint = (
        base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256()))
        .decode("utf-8")
        .replace("=", "")
    )
    return cert_pem, private_key_pem, private_key, cert_thumprint


@pytest.fixture(scope="module")
def jwt_token(client_certificate):
    _, private_key_pem, _, cert_thumprint = client_certificate
    headers = {"alg": "RS256", "kid": "testkey"}
    payload = {
        "aud": "mock_client_id",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()) - 3600,
        "active": True,
        "iss": "https://some-issuer.com",
        "cnf": {"x5t#S256": cert_thumprint},
    }
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    return token


@patch("api.auth.get_openid_configuration")
@patch("api.auth.jwt.PyJWKClient")
def test_check_token_integration(
    mock_jwk_client, mock_get_openid_config, client_certificate, jwt_token
):
    cert_pem, _, private_key, _ = client_certificate

    # Mock the OpenID configuration to use our test JWKS endpoint
    mock_get_openid_config.return_value = {"jwks_uri": "https://mock_jwks_uri"}

    # Create a mock signing key to be returned by the JWK client
    mock_jwk_client_instance = MagicMock()
    mock_jwk_client_instance.get_signing_key.return_value.key = private_key.public_key()
    mock_jwk_client.return_value = mock_jwk_client_instance

    # Act
    result, headers = api.auth.check_token(cert_pem, jwt_token)

    # Assert
    assert result["aud"] == "mock_client_id"
    assert "x-fapi-interaction-id" in headers
