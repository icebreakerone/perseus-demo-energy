import datetime
import uuid
from pydantic import BaseModel, Field, field_serializer

from . import examples


class ClientPushedAuthorizationRequest(BaseModel):
    response_type: str
    client_id: int
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    model_config = {
        "json_schema_extra": {
            "examples": [
                examples.CLIENT_PUSHED_AUTHORIZATION_REQUEST,
            ]
        }
    }


class PushedAuthorizationRequest(BaseModel):
    parameters: str
    client_id: int
    client_certificate: str
    model_config = {
        "json_schema_extra": {
            "examples": [
                examples.PUSHED_AUTHORIZATION_REQUEST,
            ]
        }
    }


class PushedAuthorizationResponse(BaseModel):
    """ """

    expires_in: int
    request_uri: str
    model_config = {
        "json_schema_extra": {
            "examples": [
                examples.PUSHED_AUTHORIZATION_RESPONSE,
            ]
        }
    }


class AuthorizationResponse(BaseModel):
    """ """

    message: str
    ticket: str
    model_config = {
        "json_schema_extra": {
            "examples": [
                examples.AUTHORIZATION_RESPONSE,
            ]
        }
    }


class TokenRequest(BaseModel):
    grant_type: str
    client_id: str
    redirect_uri: str
    code_verifier: str
    code: str
    model_config = {"json_schema_extra": {"examples": [examples.TOKEN_REQUEST]}}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    model_config = {"json_schema_extra": {"examples": [examples.TOKEN_RESPONSE]}}


class Cnf(BaseModel):
    x5t_S256: str = Field(alias="x5t#S256")


class Permission(BaseModel):
    """

    evidence - an unguessable URL which
    uses https with a public CA
    will present all the evidence, formatted as an HTML document capable of displaying in mobile portrait orientation with 320px width when the user clicks “show evidence”
    is not expected to display the content of documents or other information provided by the user to identify themselves, just the form of evidence used
    for Smart Meter data providers, must include how meter ownership was established as well as what permission was given for meter data sharing
    will contain information about all previous grants of permission and renewals for this end user for the data consumer this URL was generated for, not just for the current token

    """

    oauthIssuer: str
    client: str
    license: str
    account: str
    lastGranted: datetime.datetime
    expires: datetime.datetime
    refreshToken: str
    revoked: datetime.datetime | None
    evidenceId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    dataAvailableFrom: datetime.datetime
    tokenIssuedAt: datetime.datetime
    tokenExpires: datetime.datetime
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "oauthIssuer": "https://api.example.com/issuer",
                    "client": "https://directory.core.pilot.trust.ib1.org/member/28364528",
                    "license": "https://registry.core.pilot.trust.ib1.org/scheme/electricity/license/energy-consumption-data/2024-12-05",
                    "account": "6qIO3KZx0Q",
                    "lastGranted": "2024-03-31T23:30Z",
                    "expires": "2025-03-31T23:30Z",
                    "refreshToken": "adfjlasjklasjdkasjdklasdjkalju2318902yu89hae",
                    "evidenceId": "6f8c8b2d-4a3b-4c5e-9f1d-0f7a2e5b8c3f",
                    "revoked": "2024-07-01T12:34Z",
                    "dataAvailableFrom": "2021-07-12T00:00Z",
                    "tokenIssuedAt": "2024-06-30T23:30Z",
                    "tokenExpires": "2024-09-30T23:30Z",
                }
            ]
        }
    }

    @field_serializer("*")
    def serialize_datetimes(self, value):
        if isinstance(value, datetime.datetime):
            return (
                value.astimezone(datetime.timezone.utc).replace(tzinfo=None).isoformat()
                + "Z"
            )
        return value
