import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import pytest
from urllib.parse import quote

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
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                "https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting",
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
    return quote(cert_pem)
