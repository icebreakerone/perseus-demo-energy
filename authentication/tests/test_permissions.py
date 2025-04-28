import datetime
import uuid
from api.permissions import token_to_permission
from api.models import Permission


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
