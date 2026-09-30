import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api import audit
from api.logger import get_logger
from api.main import app
from tests import client_certificate, CLIENT_ID, TEST_ROLE

client = TestClient(app)
error_client = TestClient(app, raise_server_exceptions=False)


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


def test_missing_certificate_is_recorded(audit_lines):
    response = client.post("/api/v1/permissions", data={"token": "abc"})

    assert response.status_code == 401
    [line] = audit_lines()
    assert line["service"] == "authentication"
    assert line["route"] == "/api/v1/permissions"
    assert line["status"] == 401
    assert line["outcome"] == "client_error"
    assert line["error"] == "invalid_client"
    assert line["failure_stage"] == "cert_missing"
    assert "client_application" not in line
    assert line["request_id"] == response.headers["x-request-id"]


def test_role_failure_names_the_client(audit_lines):
    response = client.post(
        "/api/v1/permissions",
        data={"token": "abc"},
        headers={
            "x-amzn-mtls-clientcert-leaf": client_certificate(
                roles=["https://example.org/role/other"]
            )
        },
    )

    assert response.status_code == 401
    [line] = audit_lines()
    assert line["failure_stage"] == "role"
    assert line["client_application"] == CLIENT_ID
    assert line["client_roles"] == ["https://example.org/role/other"]
    assert line["client_member"]
    assert line["client_serial"]
    assert len(line["client_fingerprint"]) == 64
    assert "client_days_to_expiry" in line


@patch("api.main.conf.PROVIDER_ROLE", TEST_ROLE)
@patch("api.main.permissions.get_permission_by_token", return_value=None)
def test_token_is_named_by_reference_only(mock_get, audit_lines):
    response = client.post(
        "/api/v1/permissions",
        data={"token": "a-refresh-token-that-must-not-be-logged"},
        headers={"x-amzn-mtls-clientcert-leaf": client_certificate(roles=[TEST_ROLE])},
    )

    assert response.status_code == 404
    [line] = audit_lines()
    assert line["failure_stage"] == "permission"
    assert len(line["token_ref"]) == 12
    assert "a-refresh-token-that-must-not-be-logged" not in json.dumps(line)


@patch("api.main.store.get_request", side_effect=RuntimeError("redis is down"))
def test_unhandled_error_correlates_with_the_audit_line(mock_get, audit_lines):
    response = error_client.get(
        "/api/v1/authorize",
        params={"request_uri": "urn:ietf:params:oauth:request_uri:abc"},
    )

    assert response.status_code == 500
    [line] = audit_lines()
    assert line["status"] == 500
    assert line["outcome"] == "server_error"
    assert line["correlation_id"] == response.json()["correlation_id"]
    assert line["request_id"] == line["correlation_id"]


def test_success_is_recorded(audit_lines):
    response = client.get("/.well-known/oauth-authorization-server")

    assert response.status_code == 200
    [line] = audit_lines()
    assert line["outcome"] == "success"
    assert line["route"] == "/.well-known/oauth-authorization-server"
    assert line["level"] == "INFO"


def test_health_checks_are_not_recorded(audit_lines):
    client.get("/", headers={"user-agent": "ELB-HealthChecker/2.0"})

    assert audit_lines() == []


def test_unreadable_certificate_does_not_break_the_audit():
    assert audit.certificate_identity("not a certificate") == {
        "client_certificate": "unreadable"
    }
