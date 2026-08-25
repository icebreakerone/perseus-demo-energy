"""
The evidence page, the one human facing error path in either app.
"""

import datetime
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.main import app
from api import models

client = TestClient(app)


def a_permission() -> models.Permission:
    now = datetime.datetime.now(datetime.timezone.utc)
    return models.Permission(
        oauthIssuer="https://example.com/",
        client="https://registry.example.org/application/edp-demo",
        license="https://registry.example.org/license/energy/2026-03-12",
        account="account123",
        lastGranted=now,
        expires=now + datetime.timedelta(hours=1),
        refreshToken="mock_refresh_token",
        revoked=None,
        dataAvailableFrom=now,
        tokenIssuedAt=now,
        tokenExpires=now + datetime.timedelta(hours=1),
    )


@patch("api.evidence.permissions.get_permission_by_evidence_id")
def test_unknown_evidence_id_is_a_404(mock_get_permission):
    """
    A page that says "Not found" says so in its status too.

    It stays HTML rather than joining the JSON error shape. This is the one
    page in either app meant to be read by a person.
    """
    mock_get_permission.return_value = None

    response = client.get("/evidence/does-not-exist")

    assert response.status_code == 404
    assert "text/html" in response.headers["content-type"]
    assert "Not found" in response.text
    assert "Permission not found" in response.text


@patch("api.evidence.permissions.get_permission_by_evidence_id")
def test_known_evidence_id_renders_the_permission(mock_get_permission):
    permission = a_permission()
    mock_get_permission.return_value = permission

    response = client.get(f"/evidence/{permission.evidenceId}")

    assert response.status_code == 200
    assert permission.account in response.text
    assert permission.client in response.text
