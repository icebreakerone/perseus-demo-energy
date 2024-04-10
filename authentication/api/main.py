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
from . import authentication
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


# TODO: mock responses from FAPI api using the responses library
# response_type: str
# client_id: int
# redirect_uri: str
# code_challenge: str
# code_challenge_method: str


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
    x_amzn_mtls_clientcert: Annotated[str | None, Header()] = None,
) -> models.FAPITokenResponse:
    # TODO we need to add callbacks to add the client certificate thumbprint into the token
    # https://www.ory.sh/docs/oauth2-oidc/authorization-code-flow
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
        "client_certificate": x_amzn_mtls_clientcert,
    }
    session = requests.Session()
    session.auth = (conf.CLIENT_ID, conf.CLIENT_SECRET)
    # print(payload, conf.TOKEN_ENDPOINT)
    response = requests.post(
        f"{conf.TOKEN_ENDPOINT}",
        data=payload,
    )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    result = response.json()
    # We need to step in here to add an id_token as Ory Hydra is unable to provide this with a no-password Oauth2 client
    # so first of all we'll decode the token we receive so we can use elements of it to create our id_token
    # *important* this is due to limitations of the Ory Hydra platform, many other platforms will return an id_token as
    # part of their response
    decoded_token = jwt.decode(
        result["access_token"], options={"verify_signature": False}
    )
    id_token = auth.create_id_token(decoded_token["sub"])
    return models.FAPITokenResponse(
        access_token=result["access_token"],
        id_token=id_token,
        refresh_token=result["refresh_token"],
    )


@app.post("/api/v1/authorize/introspect")
async def introspect(
    token: models.IntrospectionRequest,
    x_amzn_mtls_clientcert: Annotated[str | None, Header()] = None,
) -> dict:
    """
    Pass the request along to the FAPI api, await the response,
    send it back to the client app
    """
    payload = {
        "token": token.token,
        "client_certificate": x_amzn_mtls_clientcert,
    }
    session = requests.Session()
    session.auth = (conf.CLIENT_ID, conf.CLIENT_SECRET)
    response = session.post(
        f"{conf.FAPI_API}/auth/introspection/",
        json=payload,
    )
    result = response.json()
    # The authentication server can use the response to make its own checks,
    return result


"""
'Fake' user authentication
"""


@app.post("/api/v1/authenticate/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> models.UserToken:
    user = authentication.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(
        minutes=authentication.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    access_token = authentication.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return models.UserToken(access_token=access_token, token_type="bearer")


@app.post("/api/v1/authenticate/consent")
async def user_consent(
    current_user: Annotated[
        models.User, Depends(authentication.get_current_active_user)
    ],
    consent: models.Consent,
):
    """
    Consent will be stored by the platform
    """
    return {
        "message": "consent granted",
        "user": current_user.username,
        "scope": consent.scopes,
    }


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
