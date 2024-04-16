from typing import Annotated
import json

import pkce
import urllib.parse
import requests
import jwt

from fastapi import FastAPI, Request, Header, HTTPException, Depends, status, Form
from fastapi.security import HTTPBasic, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse

import datetime

from . import models
from . import conf
from . import par
from . import auth

app = FastAPI(
    docs_url="/api-docs",
    title="Perseus Demo Authentication Server",
    # root_path=conf.OPEN_API_ROOT,
)


security = HTTPBasic()


@app.get("/")
async def docs() -> dict:
    return {"docs": "/api-docs"}


@app.get("/info")
async def test(request: Request) -> dict:
    return dict(request.headers.mutablecopy())


@app.post("/api/v1/par", response_model=models.PushedAuthorizationResponse)
async def pushed_authorization_request(
    response_type: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    state: Annotated[str, Form()],
    code_challenge: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    x_amzn_mtls_clientcert: Annotated[str | None, Header()] = None,
) -> dict:
    """
    Store the request in redis, return a request_uri to the client

    https://www.rfc-editor.org/rfc/rfc9126.html#section-2 - Pushed Authorization Request Endpoint
    https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2.1 - Client authentication methods
    """
    # Client authentication by mtls
    # In production the Perseus directory will be able to check certificates
    if not x_amzn_mtls_clientcert:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client certificate required",
        )

    # Get args as dict
    parameters = {
        "response_type": response_type,
        "client_id": client_id,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",  # "plain" or "S256
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scope,
    }
    print(parameters)
    token = par.get_token()
    par.store_request(token, parameters)
    return {
        "request_uri": f"urn:ietf:params:oauth:request_uri:{token}",
        "expires_in": 600,
    }


@app.get("/api/v1/authorize")
async def authorize(
    request_uri: str,
    client_id: str,
    x_amzn_mtls_clientcert: Annotated[str | None, Header()] = None,
):
    if not request_uri:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request URI required",
        )
    # Retrieve PAR data from Redis
    token = request_uri.split(":")[-1]
    par_request = par.get_request(token)
    if not par_request:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request URI does not exist or has expired",
        )
    if par_request["client_id"] != client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client ID does not match",
        )

    # Construct authorization URL with request object and PKCE parameters
    authorization_url = (
        f"{conf.AUTHORIZATION_ENDPOINT}?"
        f"client_id={conf.CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={conf.REDIRECT_URI}&"
        f"scope={par_request['scope']}&"
        f"state={par_request['state']}&"
        f"code_challenge={par_request['code_challenge']}&"
        f"code_challenge_method=S256&"
        f"request={json.dumps(par_request)}"
    )

    # Redirect the user to the authorization URL
    return RedirectResponse(authorization_url, status_code=302)


@app.post("/api/v1/authorize/token", response_model=models.FAPITokenResponse)
async def token(
    grant_type: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    code_verifier: Annotated[str, Form()],
    code: Annotated[str, Form()],
    x_amzn_mtls_clientcert: Annotated[str, Header()],
) -> models.FAPITokenResponse:
    """
    Token issuing endpoint

    We use the Ory Hydra endpoint to issue the token and validate authorisation code flow
    but due to missing features in Ory Hydra authorisation code flow we need to generate
    our own id_token, and add client certificate details to the token
    """
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    print("Token request:", x_amzn_mtls_clientcert)
    session = requests.Session()
    session.auth = (conf.CLIENT_ID, conf.CLIENT_SECRET)
    response = requests.post(
        f"{conf.TOKEN_ENDPOINT}",
        data=payload,
    )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    result = response.json()
    # Decode the Ory Hydra issued token
    decoded_token = jwt.decode(
        result["access_token"], options={"verify_signature": False}
    )
    # Add in our required client certificate thumbprint
    enhanced_token = auth.create_enhanced_access_token(
        decoded_token, x_amzn_mtls_clientcert
    )
    # Create our id_token
    id_token = auth.create_id_token(decoded_token["sub"])
    return models.FAPITokenResponse(
        access_token=enhanced_token,
        id_token=id_token,
        refresh_token=result["refresh_token"],
    )


@app.post("/api/v1/authorize/introspect")
async def introspect(
    token: models.IntrospectionRequest,
    x_amzn_mtls_clientcert: Annotated[str, Header()],
) -> dict:
    """
    We have our token as a jwt, so we can do the introspection here
    """
    print("Introspection: ", x_amzn_mtls_clientcert)
    try:
        introspection_response = auth.introspect(x_amzn_mtls_clientcert, token.token)
    except auth.AccessTokenValidatorError as e:
        raise HTTPException(status_code=401, detail=str(e))
    # The authentication server can use the response to make its own checks,
    return introspection_response


@app.get("/.well-known/openid-configuration")
async def get_openid_configuration():

    return {
        "issuer": f"{conf.ISSUER_URL}",
        "pushed_authorization_request_endpoint": f"{conf.ISSUER_URL}/auth/par/",
        "authorization_endpoint": f"{conf.ISSUER_URL}/auth/authorization/",
        "token_endpoint": f"{conf.ISSUER_URL}/auth/token/",
        "jwks_uri": f"{conf.ISSUER_URL}/.well-known/jwks.json",
        "introspection_endpoint": f"{conf.ISSUER_URL}/auth/introspection/",
        "response_types_supported": ["code", "id_token", "token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
    }


@app.get("/.well-known/jwks.json")
async def get_jwks():
    jwks = auth.create_jwks(auth.get_key("cert"))
    # Return JWKS as JSON response
    return jwks
