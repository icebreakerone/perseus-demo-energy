import datetime
from unittest.mock import patch

import pytest

from api.permissions import (
    add_license_duration,
    check_refresh,
    token_to_permission,
    revoke_permission,
    license_from_scopes,
    store_refreshed_permission,
)
from api.exceptions import (
    PermissionRefreshError,
    PermissionRevocationError,
    LicenseScopeError,
)
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


UTC = datetime.timezone.utc


def test_token_to_permission_expires_with_the_license():
    """
    The Permission lasts as long as the License says, one year, not as long
    as the access token. The refresh token lasts the Hydra lifespan.
    """
    issued = datetime.datetime(2026, 3, 15, 9, 30, tzinfo=UTC)
    decoded_token = {
        "iss": "https://example.com/",
        "client_id": "client123",
        "scp": [LICENSE, "offline_access"],
        "sub": "account123",
        "iat": int(issued.timestamp()),
        "exp": int(issued.timestamp()) + 3600,
    }

    permission = token_to_permission(decoded_token, refresh_token="rt")

    assert permission.lastGranted == issued
    assert permission.expires == datetime.datetime(2027, 3, 15, 9, 30, tzinfo=UTC)
    assert permission.tokenIssuedAt == issued
    assert permission.tokenExpires == issued + datetime.timedelta(hours=720)


@pytest.mark.parametrize(
    "start, duration, expected",
    [
        (datetime.datetime(2026, 3, 15, tzinfo=UTC), "1 year", datetime.datetime(2027, 3, 15, tzinfo=UTC)),
        (datetime.datetime(2028, 2, 29, tzinfo=UTC), "1 year", datetime.datetime(2029, 2, 28, tzinfo=UTC)),
        (datetime.datetime(2026, 1, 31, tzinfo=UTC), "1 month", datetime.datetime(2026, 2, 28, tzinfo=UTC)),
        (datetime.datetime(2026, 11, 30, tzinfo=UTC), "3 months", datetime.datetime(2027, 2, 28, tzinfo=UTC)),
        (datetime.datetime(2026, 3, 15, tzinfo=UTC), "2 years", datetime.datetime(2028, 3, 15, tzinfo=UTC)),
        (datetime.datetime(2026, 3, 15, tzinfo=UTC), "30 days", datetime.datetime(2026, 4, 14, tzinfo=UTC)),
    ],
)
def test_add_license_duration(start, duration, expected):
    assert add_license_duration(start, duration) == expected


def test_add_license_duration_rejects_unknown_unit():
    with pytest.raises(ValueError):
        add_license_duration(datetime.datetime(2026, 3, 15, tzinfo=UTC), "1 fortnight")


def stored_permission(**overrides) -> models.Permission:
    """A Permission granted 100 days ago under the one year License"""
    now = datetime.datetime.now(UTC)
    granted = now - datetime.timedelta(days=100)
    fields = dict(
        oauthIssuer="https://example.com/",
        client="https://directory.core.ib1.org/application/836153",
        license=LICENSE,
        account="account123",
        lastGranted=granted,
        expires=add_license_duration(granted, "1 year"),
        refreshToken="current-refresh-token",
        revoked=None,
        dataAvailableFrom=granted,
        tokenIssuedAt=now - datetime.timedelta(days=2),
        tokenExpires=now + datetime.timedelta(days=28),
    )
    fields.update(overrides)
    return models.Permission(**fields)


@patch("api.permissions.get_permission_by_token")
def test_check_refresh_allows_the_owning_client(mock_get_permission_by_token):
    permission = stored_permission()
    mock_get_permission_by_token.return_value = permission

    assert check_refresh("current-refresh-token", permission.client) == permission


@pytest.mark.parametrize(
    "stored, client, message",
    [
        (None, "https://directory.core.ib1.org/application/836153", "not recognised"),
        (
            stored_permission(),
            "https://directory.core.ib1.org/application/other",
            "not issued to this client",
        ),
        (
            stored_permission(revoked=datetime.datetime.now(UTC)),
            "https://directory.core.ib1.org/application/836153",
            "revoked",
        ),
        (
            stored_permission(
                lastGranted=datetime.datetime.now(UTC) - datetime.timedelta(days=400),
                expires=datetime.datetime.now(UTC) - datetime.timedelta(days=35),
            ),
            "https://directory.core.ib1.org/application/836153",
            "expired",
        ),
    ],
    ids=["unknown", "other-client", "revoked", "expired"],
)
@patch("api.permissions.get_permission_by_token")
def test_check_refresh_refuses(mock_get_permission_by_token, stored, client, message):
    mock_get_permission_by_token.return_value = stored

    with pytest.raises(PermissionRefreshError) as exc_info:
        check_refresh("some-refresh-token", client)

    assert message in str(exc_info.value)
    assert "some-refresh-token" not in str(exc_info.value)


@patch("api.permissions.get_permission_by_token")
def test_check_refresh_upgrades_a_record_holding_the_access_token_expiry(
    mock_get_permission_by_token,
):
    """
    Records written before this fix hold the access token's expiry. They are
    counted from lastGranted with the License duration instead of refused.
    """
    granted = datetime.datetime.now(UTC) - datetime.timedelta(days=10)
    mock_get_permission_by_token.return_value = stored_permission(
        lastGranted=granted, expires=granted + datetime.timedelta(hours=1)
    )

    permission = check_refresh(
        "current-refresh-token", "https://directory.core.ib1.org/application/836153"
    )

    assert permission.expires == add_license_duration(granted, "1 year")


@patch("api.permissions.write_permission")
def test_store_refreshed_permission_changes_only_the_token(mock_write_permission):
    """A refresh is not a new grant, so the grant details stay as they were"""
    permission = stored_permission()
    issued = datetime.datetime.now(UTC).replace(microsecond=0)

    refreshed = store_refreshed_permission(
        permission, {"iat": int(issued.timestamp())}, "new-refresh-token"
    )

    assert refreshed.refreshToken == "new-refresh-token"
    assert refreshed.tokenIssuedAt == issued
    assert refreshed.tokenExpires == issued + datetime.timedelta(hours=720)
    for unchanged in ("lastGranted", "expires", "evidenceId", "dataAvailableFrom"):
        assert getattr(refreshed, unchanged) == getattr(permission, unchanged)
    mock_write_permission.assert_called_once_with(refreshed)


@patch("api.permissions.write_permission")
def test_refresh_token_expiry_is_capped_at_the_permission(mock_write_permission):
    """The spec requires tokenExpires to be no later than expires"""
    now = datetime.datetime.now(UTC).replace(microsecond=0)
    permission = stored_permission(expires=now + datetime.timedelta(days=5))

    refreshed = store_refreshed_permission(
        permission, {"iat": int(now.timestamp())}, "new-refresh-token"
    )

    assert refreshed.tokenExpires == permission.expires


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

    result = revoke_permission(refresh_token, "client123")

    assert result is not None
    assert result.revoked is not None
    assert isinstance(result.revoked, datetime.datetime)
    mock_get_permission_by_token.assert_called_once_with(refresh_token)
    mock_write_permission.assert_called_once()
    # Verify the permission passed to write_permission has revoked set
    call_args = mock_write_permission.call_args[0][0]
    assert call_args.revoked is not None


@patch("api.permissions.write_permission")
@patch("api.permissions.get_permission_by_token")
def test_revoke_permission_refuses_another_client(
    mock_get_permission_by_token, mock_write_permission
):
    """
    Another Application's token is refused exactly as an unknown one is, and
    the Permission is left as it was
    """
    mock_get_permission_by_token.return_value = stored_permission()

    with pytest.raises(PermissionRevocationError) as exc_info:
        revoke_permission(
            "leaked-refresh-token", "https://directory.core.ib1.org/application/other"
        )

    assert str(exc_info.value) == "Permission not found"
    mock_write_permission.assert_not_called()


@patch("api.permissions.get_permission_by_token")
def test_revoke_permission_not_found(mock_get_permission_by_token):
    """Test permission revocation when permission is not found."""
    refresh_token = "non_existent_token"
    mock_get_permission_by_token.return_value = None

    with pytest.raises(PermissionRevocationError) as exc_info:
        revoke_permission(refresh_token, "client123")

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
        revoke_permission(refresh_token, "client123")

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
