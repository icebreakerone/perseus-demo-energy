from typing import Annotated

import urllib.parse
import requests


from fastapi import FastAPI, Request, Header, HTTPException, Depends, status, Form
from fastapi.security import HTTPBasic, OAuth2PasswordRequestForm

import datetime

from . import models
from . import conf
from . import authentication
from . import par


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
    code_challenge: Annotated[str, Form()],
    code_challenge_method: Annotated[str, Form()],
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
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    token = par.get_token()
    par.store_request(token, parameters)
    return {
        "request_uri": f"urn:ietf:params:oauth:request_uri:{token}",
        "expires_in": 600,
    }


# Test endpoint that just returns the stored request from par endpoint
@app.post("/api/v1/par/test")
async def pushed_authorization_request_test(
    auth_request: models.AuthorizationRequest,
) -> dict:
    """
    Get the stored request from redis
    """
    token = auth_request.request_uri.split(":")[-1]
    request = par.get_request(token)
    if request["client_id"] != auth_request.client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client ID does not match",
        )
    return request


@app.post("/api/v1/authorize", response_model=models.AuthorizationResponse)
async def authorization_code(
    auth_request: models.AuthorizationRequest,
) -> dict:
    """
    Pass the request along to the FAPI api, await the response,
    send it back to the client app
    """
    payload = {
        "request_uri": auth_request.request_uri,
        "client_id": auth_request.client_id,
    }
    session = requests.Session()
    session.auth = (conf.CLIENT_ID, conf.CLIENT_SECRET)
    response = session.post(
        f"{conf.FAPI_API}/auth/authorization",
        json=payload,
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    result = response.json()
    return {
        "message": "Authorisation code request issued",
        "ticket": result["ticket"],
    }


@app.post("/api/v1/authorize/issue", response_model=models.IssueResponse)
async def issue(
    current_user: Annotated[
        models.User, Depends(authentication.get_current_active_user)
    ],
    issue_request: models.IssueRequest,
) -> dict:
    """
    Send subject and ticket to the FAPI api, await the response
    """

    payload = {
        "subject": current_user.username,
        "ticket": issue_request.ticket,
    }
    session = requests.Session()
    session.auth = (conf.CLIENT_ID, conf.CLIENT_SECRET)
    response = session.post(
        f"{conf.FAPI_API}/auth/authorization/issue",
        json=payload,
    )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    result = response.json()
    return result


@app.post("/api/v1/authorize/token", response_model=models.FAPITokenResponse)
async def token(
    request: Request,
    token_request: models.FAPITokenRequest,
    x_amzn_mtls_clientcert: Annotated[str | None, Header()] = None,
) -> models.FAPITokenResponse:
    """
    Pass the request along to the FAPI api, await the response, tidy it up and
    send it back to the client app
    """
    payload = {
        "parameters": urllib.parse.urlencode(token_request.model_dump()),
        "client_id": token_request.client_id,
        "client_certificate": x_amzn_mtls_clientcert,
    }
    print(payload)
    session = requests.Session()
    session.auth = (conf.CLIENT_ID, conf.CLIENT_SECRET)
    response = session.post(
        f"{conf.FAPI_API}/auth/token/",
        json=payload,
    )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    result = response.json()
    return models.FAPITokenResponse(
        access_token=result["access_token"],
        id_token=result["id_token"],
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
