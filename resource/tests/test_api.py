import datetime
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
import pytest
from fastapi.testclient import TestClient

from tests import client_certificate, ROOT_DIR  # noqa
from api.main import app, DEMO_METER_ID
from api import conf

client = TestClient(app)


@pytest.fixture
def mock_check_token(mocker):
    return mocker.patch("api.main.auth.check_token")


@pytest.fixture
def mock_ib1_directory_get_key(mocker):
    return mocker.patch("api.provenance.get_key")


def get_private_key():
    with open(f"{ROOT_DIR}/fixtures/test-suite-key.pem") as f:
        return serialization.load_pem_private_key(
            f.read().encode(),
            password=None,
        )


@pytest.fixture
def api_consumption_url():
    from_date = datetime.date.today().isoformat()
    to_date = datetime.date.today().isoformat()
    return f"/datasources/{DEMO_METER_ID}/import?from={from_date}&to={to_date}"


def test_consumption_no_token(api_consumption_url):
    response = client.get(api_consumption_url)
    assert response.status_code == 401


def test_consumption_bad_token(api_consumption_url):

    response = client.get(
        api_consumption_url,
        headers={"Authorization": "Bearer"},
    )
    assert response.status_code == 401


def test_datasources(
    monkeypatch,
    mock_check_token,
):  # noqa
    """
    If check token passes, return datasources list and 200
    """
    monkeypatch.setattr(
        conf, "SIGNING_ROOT_CA_CERTIFICATE", f"{ROOT_DIR}/fixtures/test-suite-cert.pem"
    )
    monkeypatch.setattr(
        conf, "SIGNING_BUNDLE", f"{ROOT_DIR}/fixtures/test-suite-bundle.pem"
    )
    mock_check_token.return_value = (
        {"sub": "account123", "scp": [conf.ENERGY_CONSUMPTION_LICENSE_URL]},
        {"Date": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )

    response = client.get(
        "/datasources",
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert len(data["data"]) == 1
    assert data["data"][0]["id"] == DEMO_METER_ID
    assert data["data"][0]["type"] == "electricity"
    assert data["data"][0]["location"]["ukPostcodeOutcode"] == "SW8"
    assert data["data"][0]["availableMeasures"] == ["import", "export"]


def test_consumption(
    monkeypatch,
    mock_ib1_directory_get_key,
    mock_check_token,
    api_consumption_url,
    mocker,
):  # noqa
    """
    If check token passes, return data and 200
    """
    monkeypatch.setattr(
        conf, "SIGNING_ROOT_CA_CERTIFICATE", f"{ROOT_DIR}/fixtures/test-suite-cert.pem"
    )
    monkeypatch.setattr(
        conf, "SIGNING_BUNDLE", f"{ROOT_DIR}/fixtures/test-suite-bundle.pem"
    )
    mock_check_token.return_value = (
        {"sub": "account123", "scp": [conf.ENERGY_CONSUMPTION_LICENSE_URL]},
        {"Date": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )
    mock_ib1_directory_get_key.return_value = get_private_key()
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )

    mock_create_provenance_records = mocker.patch(
        "api.provenance.create_provenance_records"
    )
    mock_create_provenance_records.return_value = {}

    response = client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    assert response.status_code == 200
    mock_create_provenance_records.assert_called_once_with(
        from_date=mocker.ANY,
        to_date=mocker.ANY,
        permission_expires=mocker.ANY,
        permission_granted=mocker.ANY,
        account="account123",
        service_url=mocker.ANY,
        cap_member=mocker.ANY,
        # Asserted rather than ANY: the record must name the license granted on
        # the token, so this is the point the two could silently diverge.
        license_url=conf.ENERGY_CONSUMPTION_LICENSE_URL,
    )


def test_consumption_wrong_role(api_consumption_url):
    """
    A certificate with a valid signature but the wrong role is rejected with 401
    """
    pem, _, _, _ = client_certificate(
        roles=[f"{conf.SCHEME_BASE_URL}/role/some-other-role"],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )

    response = client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"
    assert "does not include role" in response.json()["error_description"]


def test_consumption_certificate_without_roles(api_consumption_url):
    """
    A certificate carrying no role extension is rejected with 401
    """
    pem, _, _, _ = client_certificate(
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )

    response = client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    assert response.status_code == 401
    assert "does not include role information" in response.json()["error_description"]


def test_consumption_certificate_without_application(api_consumption_url):
    """
    A certificate carrying no application information is rejected with 401
    """
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
    )

    response = client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    assert response.status_code == 401
    assert (
        "does not include application information"
        in response.json()["error_description"]
    )


def test_consumption_malformed_certificate(api_consumption_url):
    """
    An unparseable certificate is rejected with 401
    """
    response = client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": "not-a-certificate",
        },
    )

    assert response.status_code == 401
    assert response.json()["error_description"] == "Invalid certificate string"


# Starlette re-raises unhandled exceptions in tests unless this is off
error_client = TestClient(app, raise_server_exceptions=False)


def test_missing_token_sends_a_bare_challenge(api_consumption_url):
    """
    RFC 6750 section 3: a request carrying no credentials gets a challenge with
    no error code, because there is nothing to tell the caller they got wrong.
    """
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )

    response = client.get(
        api_consumption_url,
        headers={"x-amzn-mtls-clientcert-leaf": quote(pem)},
    )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error_description"] == "No token provided"


def test_rejected_certificate_sends_a_challenge(api_consumption_url):
    """A 401 carries the RFC 6750 challenge the IB1 guidelines ask for."""
    response = client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": "not-a-certificate",
        },
    )

    assert response.status_code == 401
    challenge = response.headers["WWW-Authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'error="invalid_token"' in challenge
    assert 'error_description="Invalid certificate string"' in challenge


def test_not_found_sends_no_challenge(
    monkeypatch, mock_check_token, mock_ib1_directory_get_key
):
    """A 404 is not an authentication failure, so there is nothing to challenge."""
    monkeypatch.setattr(
        conf, "SIGNING_ROOT_CA_CERTIFICATE", f"{ROOT_DIR}/fixtures/test-suite-cert.pem"
    )
    monkeypatch.setattr(
        conf, "SIGNING_BUNDLE", f"{ROOT_DIR}/fixtures/test-suite-bundle.pem"
    )
    mock_check_token.return_value = (
        {"sub": "account123", "scp": [conf.ENERGY_CONSUMPTION_LICENSE_URL]},
        {"Date": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )
    today = datetime.date.today().isoformat()

    response = client.get(
        f"/datasources/not-a-meter/import?from={today}&to={today}",
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    assert response.status_code == 404
    assert response.json()["error"] == "not_found"
    assert "WWW-Authenticate" not in response.headers


def test_validation_error_uses_the_api_shape(mock_check_token):
    """A missing date parameter names the parameter rather than returning a 422."""
    mock_check_token.return_value = (
        {"sub": "account123", "scp": [conf.ENERGY_CONSUMPTION_LICENSE_URL]},
        {"Date": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )

    response = client.get(
        f"/datasources/{DEMO_METER_ID}/import",
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "invalid_request"
    assert "from" in body["error_description"]
    assert "to" in body["error_description"]


def test_unhandled_error_is_reportable(api_consumption_url, mocker):
    """An infrastructure failure carries an identifier the caller can quote."""
    mocker.patch(
        "api.main.directory.parse_cert", side_effect=RuntimeError("boto is down")
    )

    response = error_client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": "anything",
        },
    )

    assert response.status_code == 500
    body = response.json()
    assert body["error"] == "server_error"
    assert len(body["correlation_id"]) == 12
    assert "boto" not in response.text.lower()


def test_malformed_bearer_token_is_rejected_not_a_server_error(api_consumption_url):
    """
    A token that is not a JWT is the caller's mistake.

    Reading the header sat outside the try in decode_with_jwks, so PyJWT's
    DecodeError escaped as a 500.
    """
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )

    response = client.get(
        api_consumption_url,
        headers={
            "Authorization": "Bearer not-a-jwt",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"
    assert 'error="invalid_token"' in response.headers["WWW-Authenticate"]


def test_unknown_measure_is_rejected(mock_check_token):
    """
    A measure outside the advertised set is refused, with the set named.

    /datasources advertises availableMeasures, and until now the consumption
    endpoint accepted anything and returned the same data regardless.
    """
    mock_check_token.return_value = (
        {"sub": "account123", "scp": [conf.ENERGY_CONSUMPTION_LICENSE_URL]},
        {"Date": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )
    today = datetime.date.today().isoformat()

    response = client.get(
        f"/datasources/{DEMO_METER_ID}/anymeasure?from={today}&to={today}",
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    assert response.status_code == 400
    description = response.json()["error_description"]
    assert "measure" in description
    # The caller is told what is allowed, which is the point of the enum
    assert "import" in description
    assert "export" in description


def test_available_measures_match_what_is_accepted(
    monkeypatch, mock_check_token, mock_ib1_directory_get_key, mocker
):
    """
    The measures /datasources advertises are exactly the ones that work.

    The two used to be unconnected, a literal in one handler and no check in
    the other.
    """
    monkeypatch.setattr(
        conf, "SIGNING_ROOT_CA_CERTIFICATE", f"{ROOT_DIR}/fixtures/test-suite-cert.pem"
    )
    monkeypatch.setattr(
        conf, "SIGNING_BUNDLE", f"{ROOT_DIR}/fixtures/test-suite-bundle.pem"
    )
    mock_check_token.return_value = (
        {"sub": "account123", "scp": [conf.ENERGY_CONSUMPTION_LICENSE_URL]},
        {"Date": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )
    mock_ib1_directory_get_key.return_value = get_private_key()
    mocker.patch("api.provenance.create_provenance_records", return_value={})
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )
    headers = {
        "Authorization": "Bearer token",
        "x-amzn-mtls-clientcert-leaf": quote(pem),
    }
    today = datetime.date.today().isoformat()

    advertised = client.get("/datasources", headers=headers).json()["data"][0][
        "availableMeasures"
    ]

    assert advertised == ["import", "export"]
    for measure in advertised:
        response = client.get(
            f"/datasources/{DEMO_METER_ID}/{measure}?from={today}&to={today}",
            headers=headers,
        )
        assert response.status_code == 200, measure


def test_measure_reaches_provenance_as_its_value(
    monkeypatch, mock_check_token, mock_ib1_directory_get_key, mocker
):
    """
    The service URL carries "import", not "Measure.IMPORT".

    A str Enum formats as its repr in an f-string, and this URL is signed into
    the provenance record.
    """
    monkeypatch.setattr(
        conf, "SIGNING_ROOT_CA_CERTIFICATE", f"{ROOT_DIR}/fixtures/test-suite-cert.pem"
    )
    monkeypatch.setattr(
        conf, "SIGNING_BUNDLE", f"{ROOT_DIR}/fixtures/test-suite-bundle.pem"
    )
    mock_check_token.return_value = (
        {"sub": "account123", "scp": [conf.ENERGY_CONSUMPTION_LICENSE_URL]},
        {"Date": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )
    mock_ib1_directory_get_key.return_value = get_private_key()
    mock_records = mocker.patch(
        "api.provenance.create_provenance_records", return_value={}
    )
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )
    today = datetime.date.today().isoformat()

    client.get(
        f"/datasources/{DEMO_METER_ID}/export?from={today}&to={today}",
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": quote(pem),
        },
    )

    service_url = mock_records.call_args.kwargs["service_url"]
    assert service_url.endswith("/export")
    assert "Measure" not in service_url
