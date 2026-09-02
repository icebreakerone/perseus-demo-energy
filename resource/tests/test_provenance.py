import datetime
import re
import pytest
from unittest.mock import MagicMock
from api import conf
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
    cap_member = "cap_member123"

    # Call the function
    result = create_provenance_records(
        from_date,
        to_date,
        permission_granted,
        permission_expires,
        service_url,
        account,
        cap_member,
        conf.ENERGY_CONSUMPTION_LICENSE_URL,
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


# Deliberately the pass through license, not the first in
# conf.ENERGY_DATA_LICENSE_URLS, so these tests fail if the record ever goes back
# to naming a fixed value rather than what was granted.
GRANTED_LICENSE = conf.ENERGY_CONSUMPTION_EMISSIONS_LICENSE_URL


def _steps(mock_record_instance) -> dict:
    """The steps passed to add_step, keyed by their `type`."""
    return {
        call.args[0]["type"]: call.args[0]
        for call in mock_record_instance.add_step.call_args_list
    }


@pytest.fixture
def provenance_steps(
    mock_get_certificate,
    mock_get_key,
    mock_record,
    mock_signer_in_memory,
    mock_certificates_provider_self_contained_record,
    mock_x509_load_pem_x509_certificates,
):
    mock_get_certificate.return_value = b"mock_certificate"
    mock_get_key.return_value = b"mock_private_key"
    mock_certificates_provider_self_contained_record.return_value = MagicMock()
    mock_x509_load_pem_x509_certificates.return_value = [MagicMock()]
    mock_signer_in_memory.return_value = MagicMock()
    mock_record_instance = mock_record.return_value
    mock_record_instance.sign.return_value = mock_record_instance
    mock_record_instance.encoded.return_value = b"mock_encoded_data"

    create_provenance_records(
        datetime.date(2023, 1, 1),
        datetime.date(2023, 1, 31),
        datetime.datetime(2023, 1, 1, 12, 0, 0),
        datetime.datetime(2023, 12, 31, 12, 0, 0),
        "https://example.com/service",
        "account123",
        "cap_member123",
        GRANTED_LICENSE,
    )
    return _steps(mock_record_instance)


def test_transfer_step_names_the_current_standard(provenance_steps):
    """
    The dated segment must be one the Registry actually publishes. The retired
    `energy-consumption-data/2024-12-05` resolved 404.
    """
    assert provenance_steps["transfer"]["standard"] == (
        f"{conf.SCHEME_BASE_URL}/standard/energy-consumption-data/2026-03-12"
    )


def test_transfer_and_permission_steps_agree_on_the_license(provenance_steps):
    """The license consented to and the license transferred under are the same."""
    assert provenance_steps["transfer"]["license"] == GRANTED_LICENSE
    assert provenance_steps["permission"]["allows"]["licenses"] == [GRANTED_LICENSE]


def test_origin_step_assurance_uses_published_vocabularies(provenance_steps):
    """
    Per the Perseus assurance metadata specification the origin signal is
    `originMethod`, under assurance/origin-method/. There is no `data-source`
    vocabulary; the source type is carried by `sourceType`.
    """
    assurance = provenance_steps["origin"]["perseus:assurance"]

    assert assurance["originMethod"] == (
        f"{conf.SCHEME_BASE_URL}/assurance/origin-method/SmartDCCOtherUser"
    )
    assert assurance["missingData"] == (
        f"{conf.SCHEME_BASE_URL}/assurance/missing-data/Missing"
    )
    assert "dataSource" not in assurance
    assert "processing" not in assurance
    assert provenance_steps["origin"]["sourceType"] == (
        f"{conf.SCHEME_BASE_URL}/source-type/Meter"
    )


def test_no_step_carries_a_retired_registry_version(provenance_steps):
    """
    Guards the whole record against the drift that left `standard` on a dated
    segment the Registry no longer publishes. Every versioned Scheme URL in the
    record must carry the current version.
    """
    versioned = re.findall(
        re.escape(conf.SCHEME_BASE_URL) + r"/\S*?(\d{4}-\d{2}-\d{2})",
        repr(provenance_steps),
    )
    assert versioned, "expected at least one versioned Scheme URL in the record"
    assert set(versioned) == {"2026-03-12"}


@pytest.fixture
def log_lines():
    """
    Capture loguru output. loguru does not feed pytest's caplog, so the sink has
    to be added by hand. Mirrors the fixture in the authentication app.
    """
    from api.logger import get_logger

    captured: list = []
    log = get_logger()
    sink_id = log.add(captured.append, format="{message}")
    yield captured
    log.remove(sink_id)


def test_does_not_log_the_signing_key(
    log_lines,
    mock_get_certificate,
    mock_get_key,
    mock_record,
    mock_signer_in_memory,
    mock_certificates_provider_self_contained_record,
    mock_x509_load_pem_x509_certificates,
):
    """
    The EDP signing key must not reach the logs.

    It was logged at INFO on every call, so it went to CloudWatch in plaintext.
    The authentication app has taken this position since token_reference() was
    added; this is the resource side equivalent.
    """
    secret = b"SIGNING-KEY-MUST-NOT-BE-LOGGED"
    mock_get_certificate.return_value = b"mock_certificate"
    mock_get_key.return_value = secret
    mock_certificates_provider_self_contained_record.return_value = MagicMock()
    mock_x509_load_pem_x509_certificates.return_value = [MagicMock()]
    mock_signer_in_memory.return_value = MagicMock()
    mock_record_instance = mock_record.return_value
    mock_record_instance.sign.return_value = mock_record_instance
    mock_record_instance.encoded.return_value = b"mock_encoded_data"

    create_provenance_records(
        datetime.date(2023, 1, 1),
        datetime.date(2023, 1, 31),
        datetime.datetime(2023, 1, 1, 12, 0, 0),
        datetime.datetime(2023, 12, 31, 12, 0, 0),
        "https://example.com/service",
        "account123",
        "cap_member123",
        GRANTED_LICENSE,
    )

    logged = "\n".join(log_lines)
    assert secret.decode() not in logged
    assert "Private key" not in logged
