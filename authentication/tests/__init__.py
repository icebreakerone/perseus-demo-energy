import os

from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from ib1.directory.extensions import encode_roles, encode_member

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
REGISTRY_URL = "https://registry.core.trust.ib1.org"
SCHEME_URL = f"{REGISTRY_URL}/scheme/perseus"
TEST_ROLE = f"{SCHEME_URL}/role/carbon-accounting-provider"
CLIENT_ID = "https://directory.core.ib1.org/application/836153"
MEMBER = "https://directory.ib1.org/member/123456"


def client_certificate(
    roles: list[str] | None = None,
    client_id: str = CLIENT_ID,
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
        certificate_builder = encode_roles(certificate_builder, roles)
    certificate_builder = encode_member(certificate_builder, MEMBER)
    certificate_builder = certificate_builder.add_extension(
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(CLIENT_ID)]),
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


# Realistic Ory Hydra (fosite) error bodies. The error_hint, error_debug and
# nested-error cases are the ones the allowlist exists to stop.
HYDRA_INVALID_GRANT = {
    "error": "invalid_grant",
    "error_description": (
        "The provided authorization grant (e.g., authorization code, resource owner "
        "credentials) or refresh token is invalid, expired, revoked, does not match "
        "the redirection URI used in the authorization request, or was issued to "
        "another client."
    ),
    "error_hint": "The PKCE code challenge did not match the code verifier.",
    "status_code": 400,
}

HYDRA_INVALID_CLIENT = {
    "error": "invalid_client",
    "error_description": (
        "Client authentication failed (e.g., unknown client, no client authentication "
        "included, or unsupported authentication method)."
    ),
    "error_hint": "The requested OAuth 2.0 Client does not exist.",
    "error_debug": "sql: no rows in result set",
    "status_code": 401,
}

HYDRA_UNSUPPORTED_TOKEN_TYPE = {
    "error": "unsupported_token_type",
    "error_description": (
        "The authorization server does not support the revocation of the presented "
        "token type."
    ),
}

HYDRA_SERVER_ERROR = {
    "error": "server_error",
    "error_description": "The authorization server encountered an unexpected condition.",
    "error_debug": "runtime error: invalid memory address",
}

# Ory returns this envelope, where `error` is an object rather than a string,
# when a request lands on a non OAuth2 path
HYDRA_HERODOT_404 = {
    "error": {
        "code": 404,
        "status": "Not Found",
        "request": "e1f0c4d2",
        "reason": "",
        "message": "404 page not found",
    }
}

PROXY_HTML_502 = (
    "<html><head><title>502 Bad Gateway</title></head>"
    "<body><h1>502 Bad Gateway</h1></body></html>"
)
