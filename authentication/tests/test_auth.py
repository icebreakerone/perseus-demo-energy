from unittest.mock import patch, MagicMock
from api.auth import certificate_has_role


@patch("api.auth.parse_cert")
def test_certificate_has_role_success(mock_parse_cert):
    # Mock certificate object
    mock_cert = MagicMock()
    mock_cert.subject.get_attributes_for_oid.return_value = [
        MagicMock(
            value="https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting"
        ),
    ]

    mock_parse_cert.return_value = mock_cert

    # Test when the role is present
    assert (
        certificate_has_role(
            "https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting",
            "mock_quoted_certificate",
        )
        is True
    )


@patch("api.auth.parse_cert")
def test_certificate_has_role_failure(mock_parse_cert):
    # Mock certificate object
    mock_cert = MagicMock()
    mock_cert.subject.get_attributes_for_oid.return_value = [
        MagicMock(value="another-role@another-tf")
    ]

    mock_parse_cert.return_value = mock_cert

    # Test when the role is not present
    assert certificate_has_role("Admin", "mock_quoted_certificate") is False


@patch("api.auth.parse_cert")
def test_certificate_has_role_empty_roles(mock_parse_cert):
    # Mock certificate object with no roles
    mock_cert = MagicMock()
    mock_cert.subject.get_attributes_for_oid.return_value = []

    mock_parse_cert.return_value = mock_cert

    # Test when there are no roles in the certificate
    assert (
        certificate_has_role("another-role@another-tf", "mock_quoted_certificate")
        is False
    )
