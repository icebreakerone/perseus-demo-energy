import os
import datetime
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import pytest

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_ID = "https://directory.core.demo.ib1.org/member/81524"


@pytest.fixture(scope="module")
def client_certificate():
    # Generate a self-signed certificate for testing
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "London"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, "carbon-accounting@perseus"
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                CLIENT_ID,
            ),
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
