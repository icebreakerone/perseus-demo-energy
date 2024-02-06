from pydantic import BaseModel
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
    clientId: int
    clientCertificate: str
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
                examples.PUSHED_AUTHORIZATION_REQUEST,
            ]
        }
    }


class AuthorizationRequest(BaseModel):
    request_uri: str
    client_id: int
    model_config = {
        "json_schema_extra": {
            "examples": [
                examples.AUTHORIZATION_REQUEST,
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


class IssueRequest(BaseModel):
    ticket: str


class IssueResponse(BaseModel):
    type: str
    resultCode: str
    resultMessage: str
    accessTokenDuration: int
    accessTokenExpiresAt: int
    action: str
    authorizationCode: str
    idToken: str
    responseContent: str
    model_config = {
        "json_schema_extra": {
            "examples": [
                examples.ISSUE_RESPONSE,
            ]
        }
    }


class FAPITokenRequest(BaseModel):
    client_id: int
    parameters: str
    model_config = {"json_schema_extra": {"examples": [examples.TOKEN_REQUEST]}}


class FAPITokenResponse(BaseModel):
    access_token: str
    id_token: str
    refresh_token: str
    model_config = {"json_schema_extra": {"examples": [examples.TOKEN_RESPONSE]}}


# Models for user authentication demo


class UserToken(BaseModel):
    access_token: str
    token_type: str


class UserTokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


class Consent(BaseModel):
    scopes: list[str]
    model_config = {
        "json_schema_extra": {"examples": [{"scopes": ["openid", "profile"]}]}
    }
