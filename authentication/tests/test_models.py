import datetime

from api.models import Permission


def test_permission_serializer():
    test_permission = Permission(
        oauthIssuer="https://api.example.com/issuer",
        client="https://directory.core.pilot.trust.ib1.org/member/28364528",
        license="https://registry.core.pilot.trust.ib1.org/scheme/electricity/license/energy-consumption-data/2024-12-05",
        account="6qIO3KZx0Q",
        lastGranted=datetime.datetime.now(datetime.timezone.utc),
        expires="2025-03-31T23:30Z",
        refreshToken="adfjlasjklasjdkasjdklasdjkalju2318902yu89hae",
        revoked=None,
        dataAvailableFrom=datetime.datetime.now(datetime.timezone.utc),
        tokenIssuedAt=datetime.datetime.now(datetime.timezone.utc),
        tokenExpires=datetime.datetime.now(datetime.timezone.utc),
    )
    print(test_permission.model_dump())
