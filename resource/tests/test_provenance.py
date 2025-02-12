import datetime
import pytest
from unittest.mock import MagicMock
from api.provenance import create_provenance_records


@pytest.fixture
def mock_get_certificate(mocker):
    return mocker.patch("api.provenance.get_certificate")


@pytest.fixture
def mock_get_key(mocker):
    return mocker.patch("api.provenance.get_key")


@pytest.fixture
def mock_record(mocker):
    return mocker.patch("api.provenance.Record")


@pytest.fixture
def mock_signer_in_memory(mocker):
    return mocker.patch("api.provenance.SignerInMemory")


@pytest.fixture
def mock_certificates_provider_self_contained_record(mocker):
    return mocker.patch("api.provenance.CertificatesProviderSelfContainedRecord")


@pytest.fixture
def mock_x509_load_pem_x509_certificates(mocker):
    return mocker.patch("api.provenance.x509.load_pem_x509_certificates")


def test_create_provenance_records(
    mock_get_certificate,
    mock_get_key,
    mock_record,
    mock_signer_in_memory,
    mock_certificates_provider_self_contained_record,
    mock_x509_load_pem_x509_certificates,
):
    # Mock return values
    mock_get_certificate.return_value = b"mock_certificate"
    mock_get_key.return_value = b"mock_private_key"
    mock_certificates_provider_self_contained_record.return_value = MagicMock()
    mock_x509_load_pem_x509_certificates.return_value = [MagicMock()]
    mock_signer_in_memory.return_value = MagicMock()
    mock_record_instance = mock_record.return_value
    mock_record_instance.sign.return_value = mock_record_instance
    mock_record_instance.encoded.return_value = b"mock_encoded_data"

    # Test data
    from_date = datetime.date(2023, 1, 1)
    to_date = datetime.date(2023, 1, 31)
    permission_granted = datetime.datetime(2023, 1, 1, 12, 0, 0)
    permission_expires = datetime.datetime(2023, 12, 31, 12, 0, 0)
    service_url = "https://example.com/service"
    account = "account123"
    fapi_id = "fapi123"
    cap_member = "cap_member123"

    # Call the function
    result = create_provenance_records(
        from_date,
        to_date,
        permission_granted,
        permission_expires,
        service_url,
        account,
        fapi_id,
        cap_member,
    )

    # Assertions
    assert result == b"mock_encoded_data"
    mock_get_certificate.assert_called()
    mock_get_key.assert_called()
    mock_certificates_provider_self_contained_record.assert_called()
    mock_x509_load_pem_x509_certificates.assert_called()
    mock_signer_in_memory.assert_called()
    mock_record_instance.add_step.assert_called()
    mock_record_instance.sign.assert_called()
    mock_record_instance.encoded.assert_called()
