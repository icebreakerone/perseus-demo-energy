import datetime
import json
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from api import audit, conf
from api.logger import get_logger
from api.main import app, DEMO_METER_ID
from tests import client_certificate

client = TestClient(app)
error_client = TestClient(app, raise_server_exceptions=False)

MEMBER = "https://directory.ib1.org/member/123456"


@pytest.fixture
def audit_lines():
    """The audit lines written while the test runs, parsed."""
    captured: list = []
    log = get_logger()
    sink_id = log.add(captured.append, format=lambda record: "{extra[_json]}")
    yield lambda: [
        line
        for line in (json.loads(raw) for raw in captured)
        if line.get("event") == "request"
    ]
    log.remove(sink_id)


@pytest.fixture
def consumption_url():
    to_date = datetime.date.today()
    from_date = to_date - datetime.timedelta(days=7)
    return (
        f"/datasources/{DEMO_METER_ID}/import"
        f"?from={from_date.isoformat()}&to={to_date.isoformat()}"
    )


def certificate(roles=None) -> str:
    pem, _, _, _ = client_certificate(
        roles=roles if roles is not None else [conf.PROVIDER_ROLE],
        member=MEMBER,
        add_application=True,
    )
    return quote(pem)


def test_successful_read_names_client_account_and_data(
    monkeypatch, mocker, consumption_url, audit_lines
):
    mocker.patch(
        "api.main.auth.check_token",
        return_value=(
            {"sub": "account123", "scp": [conf.ENERGY_CONSUMPTION_LICENSE_URL]},
            {},
        ),
    )
    mocker.patch("api.provenance.create_provenance_records", return_value={})

    response = client.get(
        consumption_url,
        headers={
            "Authorization": "Bearer a-token-that-must-not-be-logged",
            "x-amzn-mtls-clientcert-leaf": certificate(),
        },
    )

    assert response.status_code == 200
    [line] = audit_lines()
    assert line["service"] == "resource"
    assert line["route"] == "/datasources/{id}/{measure}"
    assert line["outcome"] == "success"
    assert line["client_member"] == MEMBER
    assert line["client_application"]
    assert line["account"] == "account123"
    assert line["license"] == conf.ENERGY_CONSUMPTION_LICENSE_URL
    assert line["datasource"] == DEMO_METER_ID
    assert line["measure"] == "import"
    assert line["readings"] > 0
    assert "a-token-that-must-not-be-logged" not in json.dumps(line)


def test_wrong_role_is_recorded(consumption_url, audit_lines):
    response = client.get(
        consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": certificate(
                roles=["https://example.org/role/other"]
            ),
        },
    )

    assert response.status_code == 401
    [line] = audit_lines()
    assert line["outcome"] == "client_error"
    assert line["failure_stage"] == "role"
    assert line["error"] == "invalid_token"
    assert line["client_member"] == MEMBER


def test_missing_token_is_recorded(consumption_url, audit_lines):
    response = client.get(
        consumption_url, headers={"x-amzn-mtls-clientcert-leaf": certificate()}
    )

    assert response.status_code == 401
    [line] = audit_lines()
    assert line["failure_stage"] == "token_missing"
    assert line["request_id"] == response.headers["x-request-id"]


def test_rejected_token_is_recorded(mocker, consumption_url, audit_lines):
    from api.exceptions import AccessTokenAudienceError

    mocker.patch(
        "api.main.auth.check_token",
        side_effect=AccessTokenAudienceError("Invalid Client ID"),
    )

    response = client.get(
        consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": certificate(),
        },
    )

    assert response.status_code == 401
    [line] = audit_lines()
    assert line["failure_stage"] == "token"
    assert line["error_description"] == "Invalid Client ID"


def test_unhandled_error_correlates_with_the_audit_line(
    mocker, consumption_url, audit_lines
):
    mocker.patch("api.main.directory.parse_cert", side_effect=RuntimeError("down"))

    response = error_client.get(
        consumption_url,
        headers={
            "Authorization": "Bearer token",
            "x-amzn-mtls-clientcert-leaf": "anything",
        },
    )

    assert response.status_code == 500
    [line] = audit_lines()
    assert line["outcome"] == "server_error"
    assert line["correlation_id"] == response.json()["correlation_id"]


def test_certificate_is_read_from_the_lambda_event():
    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE], member=MEMBER, add_application=True
    )
    scope = {
        "headers": [],
        "aws.event": {
            "requestContext": {"authentication": {"clientCert": {"clientCertPem": pem}}}
        },
    }

    assert (
        audit.certificate_identity(audit.certificate_pem(scope))["client_member"]
        == MEMBER
    )
