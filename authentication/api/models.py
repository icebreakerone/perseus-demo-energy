from pydantic import BaseModel, Field
from typing import Any
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


class AuthorizationRequest(BaseModel):
    request_uri: str
    client_id: str
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


class TokenRequest(BaseModel):
    grant_type: str
    client_id: str
    redirect_uri: str
    code_verifier: str
    code: str
    model_config = {"json_schema_extra": {"examples": [examples.TOKEN_REQUEST]}}


class TokenResponse(BaseModel):
    access_token: str
    id_token: str
    refresh_token: str
    model_config = {"json_schema_extra": {"examples": [examples.TOKEN_RESPONSE]}}


class IntrospectionRequest(BaseModel):
    token: str
    model_config = {
        "json_schema_extra": {
            "examples": [
                {"token": "SUtEVc3T"},
            ]
        }
    }


class Cnf(BaseModel):
    x5t_S256: str = Field(alias="x5t#S256")


class IntrospectionResponse(BaseModel):
    aud: list[str]
    client_id: str
    exp: int
    ext: dict[str, Any]
    iat: int
    iss: str
    jti: str
    nbf: int
    scp: list[str]
    sub: str
    cnf: Cnf
    active: bool
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "aud": [],
                    "client_id": "f67916ce-de33-4e2f-a8e3-cbd5f6459c30",
                    "exp": 1713285925,
                    "ext": {},
                    "iat": 1713282325,
                    "iss": "https://vigorous-heyrovsky-1trvv0ikx9.projects.oryapis.com",
                    "jti": "cca497f5-f3b0-4c81-b873-7f97a74cfcda",
                    "nbf": 1713282325,
                    "scp": ["profile", "offline_access"],
                    "sub": "d6fd6e1c-a10e-40d8-aa2b-9606f3d34d3c",
                    "cnf": {"x5t#S256": "k6Joc_TbRIm_vIQyrWcMTIVz_QZmR0JReGASWRcLdnQ"},
                    "active": True,
                }
            ]
        }
    }


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
