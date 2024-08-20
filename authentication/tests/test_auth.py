from unittest.mock import patch, MagicMock
from api.auth import require_role


@patch("api.auth.parse_cert")
def test_require_role_success(mock_parse_cert):
    # Mock certificate object
    mock_cert = MagicMock()
    mock_cert.subject.get_attributes_for_oid.return_value = [
        MagicMock(value="carbon-accounting@perseus"),
    ]

    mock_parse_cert.return_value = mock_cert

    # Test when the role is present
    assert require_role("carbon-accounting@perseus", "mock_quoted_certificate") is True


@patch("api.auth.parse_cert")
def test_require_role_failure(mock_parse_cert):
    # Mock certificate object
    mock_cert = MagicMock()
    mock_cert.subject.get_attributes_for_oid.return_value = [
        MagicMock(value="another-role@another-tf")
    ]

    mock_parse_cert.return_value = mock_cert

    # Test when the role is not present
    assert require_role("Admin", "mock_quoted_certificate") is False


@patch("api.auth.parse_cert")
def test_require_role_empty_roles(mock_parse_cert):
    # Mock certificate object with no roles
    mock_cert = MagicMock()
    mock_cert.subject.get_attributes_for_oid.return_value = []

    mock_parse_cert.return_value = mock_cert

    # Test when there are no roles in the certificate
    assert require_role("another-role@another-tf", "mock_quoted_certificate") is False
