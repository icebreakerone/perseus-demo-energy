import datetime
from unittest.mock import patch

import pytest

from api.permissions import token_to_permission, revoke_permission
from api.exceptions import PermissionRevocationError
from api import models


def test_token_to_permission():
    decoded_token = {
        "iss": "https://example.com/",
        "client_id": "client123",
        "scp": ["read"],
        "sub": "account123",
        "iat": 1698765432,
        "exp": 1698769032,
        "ext": {"evidence": "some_evidence"},
    }

    permission = token_to_permission(decoded_token, refresh_token="any-thing")

    assert permission.oauthIssuer == decoded_token["iss"]
    assert type(permission.lastGranted) is datetime.datetime
    assert type(permission.expires) is datetime.datetime
    assert permission.revoked is None
    assert type(permission.tokenIssuedAt) is datetime.datetime
    assert type(permission.tokenExpires) is datetime.datetime


@patch("api.permissions.write_permission")
@patch("api.permissions.get_permission_by_token")
def test_revoke_permission_success(mock_get_permission_by_token, mock_write_permission):
    """Test successful permission revocation."""
    refresh_token = "test_refresh_token"
    permission = models.Permission(
        oauthIssuer="https://example.com/",
        client="client123",
        license="https://example.com/license",
        account="account123",
        lastGranted=datetime.datetime.now(datetime.timezone.utc),
        expires=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        refreshToken=refresh_token,
        revoked=None,
        dataAvailableFrom=datetime.datetime.now(datetime.timezone.utc),
        tokenIssuedAt=datetime.datetime.now(datetime.timezone.utc),
        tokenExpires=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
    )
    mock_get_permission_by_token.return_value = permission

    result = revoke_permission(refresh_token)

    assert result is not None
    assert result.revoked is not None
    assert isinstance(result.revoked, datetime.datetime)
    mock_get_permission_by_token.assert_called_once_with(refresh_token)
    mock_write_permission.assert_called_once()
    # Verify the permission passed to write_permission has revoked set
    call_args = mock_write_permission.call_args[0][0]
    assert call_args.revoked is not None


@patch("api.permissions.get_permission_by_token")
def test_revoke_permission_not_found(mock_get_permission_by_token):
    """Test permission revocation when permission is not found."""
    refresh_token = "non_existent_token"
    mock_get_permission_by_token.return_value = None

    with pytest.raises(PermissionRevocationError) as exc_info:
        revoke_permission(refresh_token)

    assert "Permission not found" in str(exc_info.value)
    assert refresh_token in str(exc_info.value)
    mock_get_permission_by_token.assert_called_once_with(refresh_token)


@patch("api.permissions.write_permission")
@patch("api.permissions.get_permission_by_token")
def test_revoke_permission_write_error(mock_get_permission_by_token, mock_write_permission):
    """Test permission revocation when write fails."""
    refresh_token = "test_refresh_token"
    permission = models.Permission(
        oauthIssuer="https://example.com/",
        client="client123",
        license="https://example.com/license",
        account="account123",
        lastGranted=datetime.datetime.now(datetime.timezone.utc),
        expires=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        refreshToken=refresh_token,
        revoked=None,
        dataAvailableFrom=datetime.datetime.now(datetime.timezone.utc),
        tokenIssuedAt=datetime.datetime.now(datetime.timezone.utc),
        tokenExpires=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
    )
    mock_get_permission_by_token.return_value = permission
    mock_write_permission.side_effect = Exception("Database error")

    with pytest.raises(PermissionRevocationError) as exc_info:
        revoke_permission(refresh_token)

    assert "Error revoking permission" in str(exc_info.value)
    assert "Database error" in str(exc_info.value)
