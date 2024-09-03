import os

from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import base64
from api import certificate_extensions

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
REGISTRY_URL = "https://registry.core.ib1.org"
SCHEME_URL = f"{REGISTRY_URL}/scheme/perseus"
TEST_ROLE = f"{SCHEME_URL}/role/carbon-accounting"
CLIENT_ID = "https://directory.core.ib1.org/member/836153"


def client_certificate(
    roles: list[str] | None = None,
) -> str:
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    # Define certificate details
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "London"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Core Trust Framework"),
            x509.NameAttribute(
                NameOID.COMMON_NAME, "Core Trust Framework Client Issuer"
            ),
        ]
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "London"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Carbon Accounting app"),
            x509.NameAttribute(NameOID.COMMON_NAME, CLIENT_ID),
        ]
    )

    # Create certificate builder
    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(int("68dc60d6bf90e1054d1624508e7fecaacec5555c", 16))
        .not_valid_before(datetime.strptime("2024-08-28 12:51:03", "%Y-%m-%d %H:%M:%S"))
        .not_valid_after(datetime.strptime("2025-08-28 12:51:03", "%Y-%m-%d %H:%M:%S"))
    )
    if roles:
        certificate_builder = certificate_builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.62329.1.1"),
                certificate_extensions.encode(roles),
            ),
            critical=False,
        )

    # Sign the certificate
    certificate = certificate_builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )
    # Encode the certificate to PEM format
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    # Calculate the thumbprint of the certificate
    return cert_pem
