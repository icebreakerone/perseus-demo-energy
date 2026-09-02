import datetime
from unittest.mock import patch

import pytest

from api.permissions import (
    token_to_permission,
    revoke_permission,
    license_from_scopes,
)
from api.exceptions import PermissionRevocationError, LicenseScopeError
from api import conf
from api import models

LICENSE = conf.ENERGY_CONSUMPTION_LICENSE_URL
PASS_THROUGH_LICENSE = conf.ENERGY_CONSUMPTION_EMISSIONS_LICENSE_URL


def test_token_to_permission():
    decoded_token = {
        "iss": "https://example.com/",
        "client_id": "client123",
        "scp": [LICENSE, "offline_access"],
        "sub": "account123",
        "iat": 1698765432,
        "exp": 1698769032,
        "ext": {"evidence": "some_evidence"},
    }

    permission = token_to_permission(decoded_token, refresh_token="any-thing")

    assert permission.license == LICENSE
    assert permission.oauthIssuer == decoded_token["iss"]
    assert type(permission.lastGranted) is datetime.datetime
    assert type(permission.expires) is datetime.datetime
    assert permission.revoked is None
    assert type(permission.tokenIssuedAt) is datetime.datetime
    assert type(permission.tokenExpires) is datetime.datetime


def test_license_from_scopes_ignores_order():
    """
    The license must be selected by what it is, not by its position. Hydra is
    free to return the granted scopes in any order.
    """
    assert license_from_scopes(["offline_access", LICENSE]) == LICENSE


def test_license_from_scopes_ignores_non_license_scopes():
    """
    A role URL is not a license. Roles come from the client certificate, and one
    registered as an OAuth scope must not end up in the Permission Record.
    """
    scopes = [
        "openid",
        "offline_access",
        f"{conf.SCHEME_BASE_URL}/role/carbon-accounting-provider",
        LICENSE,
    ]
    assert license_from_scopes(scopes) == LICENSE


def test_license_from_scopes_accepts_the_pass_through_license():
    """
    Both licences are valid for the energy consumption data API, the Scheme
    Catalog Requirements carry ib1:requireOneOrMoreOf on dcterms:license.
    """
    assert (
        license_from_scopes([PASS_THROUGH_LICENSE, "offline_access"])
        == PASS_THROUGH_LICENSE
    )


def test_license_from_scopes_rejects_no_license():
    """A token with no license scope means the authorization server is misconfigured."""
    with pytest.raises(LicenseScopeError):
        license_from_scopes(["offline_access"])


def test_license_from_scopes_rejects_empty_scopes():
    """Previously an unguarded index, which raised IndexError."""
    with pytest.raises(LicenseScopeError):
        license_from_scopes([])


def test_license_from_scopes_rejects_ambiguous():
    """Two licenses give no basis to choose which the user consented to."""
    with pytest.raises(LicenseScopeError):
        license_from_scopes(
            [LICENSE, f"{conf.SCHEME_BASE_URL}/license/other/2026-03-12"]
        )


def test_license_from_scopes_ignores_other_environments():
    """
    A license from a different Registry environment is not this deployment's
    license, and must not be silently accepted.
    """
    pilot = (
        "https://registry.core.pilot.trust.ib1.org/scheme/perseus"
        "/license/energy-consumption-edp-cap/2026-03-12"
    )
    with pytest.raises(LicenseScopeError):
        license_from_scopes([pilot, "offline_access"])



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
    # The caller supplied the token, echoing it back adds nothing and puts the
    # credential into logs and error responses
    assert refresh_token not in str(exc_info.value)
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

    assert "Could not revoke permission" in str(exc_info.value)
    # The underlying failure goes to the logs, not to the caller
    assert "Database error" not in str(exc_info.value)
    assert refresh_token not in str(exc_info.value)


def test_token_reference_does_not_expose_the_token():
    """The log reference for a token is short, stable, and not reversible."""
    from api.permissions import token_reference

    token = "ory_rt_a_real_looking_refresh_token"
    reference = token_reference(token)

    assert token not in reference
    assert len(reference) == 12
    assert reference == token_reference(token)
    assert reference != token_reference(token + "x")
