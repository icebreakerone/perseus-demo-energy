import pytest


from tests import client_certificate, TEST_ROLE, SCHEME_URL

# from auth import require_role
from api.auth import require_role

from api.exceptions import (
    CertificateRoleMissingError,
    CertificateRoleError,
    CertificateMissingError,
)


def test_role_in_certificate():
    cert_urlencoded = client_certificate(
        roles=[
            TEST_ROLE,
            f"{SCHEME_URL}/role/another-role",
        ]
    )
    require_role(  # No assertion, just checking for exceptions
        TEST_ROLE,
        cert_urlencoded,
    )


def test_role_not_in_certificate():
    cert_urlencoded = client_certificate(
        roles=[
            f"{SCHEME_URL}/role/another-role",
        ]
    )
    with pytest.raises(CertificateRoleError):
        require_role(TEST_ROLE, cert_urlencoded)


def test_certificate_with_no_roles():
    cert_urlencoded = client_certificate()
    with pytest.raises(CertificateRoleMissingError):
        require_role(
            TEST_ROLE,
            cert_urlencoded,
        )


def test_empty_role():
    cert_urlencoded = client_certificate(roles=[""])
    with pytest.raises(CertificateRoleError):
        require_role(
            TEST_ROLE,
            cert_urlencoded,
        )


def test_no_certificate_supplied():
    with pytest.raises(CertificateMissingError):
        require_role(
            TEST_ROLE,
            None,
        )


def test_bad_certificate():
    with pytest.raises(ValueError):
        require_role(
            TEST_ROLE,
            "Not a PEM encoded certificate",
        )
