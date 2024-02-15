from typing import Annotated
import json

import urllib.parse
import requests


from fastapi import FastAPI, Request, Header, HTTPException, Depends, status
from fastapi.security import HTTPBasic, OAuth2PasswordRequestForm

import datetime

from . import models
from . import conf
from . import authentication

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
    par: models.ClientPushedAuthorizationRequest,
    x_amzn_mtls_clientcert: Annotated[str | None, Header()] = None,
) -> dict:
    """
    Pass the request along to the FAPI api, await the response,
    send it back to the client app
    """
    print(x_amzn_mtls_clientcert)
    payload = {
        "parameters": urllib.parse.urlencode(par.model_dump()),
        "client_id": par.client_id,
        "client_certificate": x_amzn_mtls_clientcert,
    }
    session = requests.Session()
    session.auth = (conf.CLIENT_ID, conf.CLIENT_SECRET)
    response = session.post(
        f"{conf.FAPI_API}/auth/par/",
        json=payload,
    )
    result = response.json()
    try:
        data = json.loads(result["response_content"])
    except KeyError:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Unexpected response from FAPI",
                "response": result,
                "request": payload,
            },
        )
    return data


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


# TODO is it authenticate and authorize or authentication and authorzation?
@app.post("/api/v1/authorize/token", response_model=models.FAPITokenResponse)
async def token(
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
    session = requests.Session()
    session.auth = (conf.CLIENT_ID, conf.CLIENT_SECRET)
    response = session.post(
        f"{conf.FAPI_API}/auth/token/",
        json=payload,
    )
    if response.status_code != 200:
        print(response.text)
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
