from typing import Annotated
import json


from fastapi import (
    FastAPI,
    Request,
    Header,
    HTTPException,
    status,
    Form,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import Response
from ib1 import directory
from . import models
from . import conf
from . import par
from . import auth
from .logger import get_logger

logger = get_logger()
app = FastAPI(
    docs_url="/api-docs",
    title="Perseus Demo Authentication Server",
    # root_path=conf.OPEN_API_ROOT,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def docs() -> dict:
    return {"docs": "/api-docs"}


@app.post(
    "/api/v1/par", response_model=models.PushedAuthorizationResponse, status_code=201
)
async def pushed_authorization_request(
    response_type: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    code_challenge: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    request: Request,
    x_amzn_mtls_clientcert_leaf: Annotated[str | None, Header()] = None,
) -> dict:
    """
    Store the request in redis, return a request_uri to the client

    For more information see:

    - [Pushed Authorization Request Endpoint](https://www.rfc-editor.org/rfc/rfc9126.html#section-2)
    - [Client authentication methods](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2.1)
    """
    # Client authentication by mtls
    if not x_amzn_mtls_clientcert_leaf:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client certificate required",
        )

    client_cert = directory.parse_cert(x_amzn_mtls_clientcert_leaf)
    client_id = directory.extensions.decode_application(client_cert)
    # Get args as dict
    parameters = {
        "response_type": response_type,
        "code_challenge": code_challenge,
        "client_id": client_id,
        "code_challenge_method": "S256",  # "plain" or "S256
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": auth.create_state_token(
            {"client_id": client_id}
        ),  # For ory hydra interaction
    }
    token = par.get_token()
    par.store_request(token, parameters)
    return {
        "request_uri": f"urn:ietf:params:oauth:request_uri:{token}",
        "expires_in": 600,
    }


@app.get(
    "/api/v1/authorize",
    responses={
        302: {
            "description": "Redirects to authentication and consent",
            "headers": {
                "Location": {
                    "description": "The URL to which the client should be redirected",
                }
            },
        },
        200: {"description": "This response is not expected.", "model": None},
    },
)
async def authorize(
    request_uri: str,
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

    authorization_url = (
        f"{conf.ORY_AUTHORIZATION_ENDPOINT}?"
        f"client_id={conf.ORY_CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={par_request['redirect_uri']}&"
        f"scope={par_request['scope']}&"
        f"code_challenge={par_request['code_challenge']}&"
        f"code_challenge_method=S256&"
        f"request={json.dumps(par_request)}&"
        f"state={par_request['state']}"
    )
    logger.info(f"Redirecting to {authorization_url}")
    # Redirect the user to the authorization URL
    return Response(status_code=302, headers={"Location": authorization_url})


@app.post("/api/v1/authorize/token", response_model=models.TokenResponse)
async def token(
    grant_type: Annotated[str, Form()],
    x_amzn_mtls_clientcert_leaf: Annotated[str | None, Header()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    code: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
) -> models.TokenResponse:
    """
    Token issuing endpoint

    We use the Ory Hydra endpoint to issue the token and validate authorisation code flow
    but due to missing features in Ory Hydra authorisation code flow we need to generate
    our own id_token, and add client certificate details to the token
    """
    if x_amzn_mtls_clientcert_leaf is None:
        raise HTTPException(status_code=401, detail="No client certificate provided")
    client_cert = directory.parse_cert(x_amzn_mtls_clientcert_leaf)
    try:
        directory.require_role(
            conf.PROVIDER_ROLE,
            client_cert,
        )
    except directory.CertificateRoleError as e:
        raise HTTPException(
            status_code=401,
            detail=str(e),
        )
    if grant_type == "authorization_code":
        logger.info("Authorization code flow")
        if not code or not code_verifier or not redirect_uri:
            raise HTTPException(status_code=400, detail="Missing required parameters")

        payload = {
            "grant_type": grant_type,
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": conf.ORY_CLIENT_ID,
            "code_verifier": code_verifier,
        }
    elif grant_type == "refresh_token":
        logger.info("Refresh token flow")
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Missing refresh token")

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": conf.ORY_CLIENT_ID,
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid grant type")
    session = auth.get_session()

    response = session.post(
        f"{conf.ORY_TOKEN_ENDPOINT}",
        data=payload,
    )
    logger.info(f"Token response: {response.status_code} {response.text}")
    if response.status_code != 200:
        logger.error(response.text)
        raise HTTPException(status_code=response.status_code, detail=response.text)
    result = response.json()
    logger.info(f"Token result: {result}")
    # Add in our required client certificate thumbprint
    enhanced_token = auth.create_enhanced_access_token(
        result["access_token"],
        x_amzn_mtls_clientcert_leaf,
        f"{conf.ORY_URL}/.well-known/jwks.json",
    )
    logger.info(f"Enhanced token: {enhanced_token}")
    return models.TokenResponse(
        access_token=enhanced_token,
        refresh_token=result.get("refresh_token"),
    )


@app.post("/api/v1/authorize/revoke")
async def revoke_token(
    request: Request,
    token: str = Form(...),
    token_type_hint: str = Form(None),
    x_amzn_mtls_clientcert_leaf: str | None = Header(None),
):
    """
    Token revocation endpoint

    - Requires mTLS authentication (client certificate validation)
    - Calls Ory Hydra's token revocation endpoint
    - Supports both access and refresh token revocation
    """

    # Ensure client provided an mTLS certificate
    if x_amzn_mtls_clientcert_leaf is None:
        raise HTTPException(status_code=401, detail="No client certificate provided")

    # Validate client certificate (ensure it's authorized)
    client_cert = directory.parse_cert(x_amzn_mtls_clientcert_leaf)
    try:
        directory.require_role(
            conf.PROVIDER_ROLE,
            client_cert,
        )
    except directory.CertificateRoleError as e:
        raise HTTPException(status_code=401, detail=str(e))

    # Prepare revocation request to Hydra
    payload = {"token": token, "token_type_hint": token_type_hint}
    session = auth.get_session()

    response = session.post(
        f"{conf.ORY_URL}/oauth2/revoke",
        data=payload,
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    return {"status": "success", "message": "Token revoked"}


@app.get("/.well-known/oauth-authorization-server")
async def get_openid_configuration():
    logger.info("Getting Oauth configuration")
    return {
        "issuer": conf.ISSUER_URL,
        "authorization_endpoint": f"{conf.UNPROTECTED_URL}/api/v1/authorize",
        "pushed_authorization_request_endpoint": f"{conf.ISSUER_URL}/api/v1/par",
        "token_endpoint": f"{conf.ISSUER_URL}/api/v1/authorize/token",
        "revocation_endpoint": f"{conf.ISSUER_URL}/api/v1/authorize/revoke",
        "jwks_uri": f"{conf.UNPROTECTED_URL}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["tls_client_auth"],
        "require_pushed_authorization_requests": True,
        "code_challenge_methods_supported": ["S256"],
        "mtls_endpoint_aliases": {
            "authorization_endpoint": f"{conf.UNPROTECTED_URL}/api/v1/authorize",
            "pushed_authorization_request_endpoint": f"{conf.ISSUER_URL}/api/v1/par",
            "token_endpoint": f"{conf.ISSUER_URL}/api/v1/authorize/token",
            "revocation_endpoint": f"{conf.ISSUER_URL}/api/v1/authorize/revoke",
        },
        "tls_client_certificate_bound_access_tokens": True,
        "authorization_response_iss_parameter_supported": True,
        "request_object_signing_alg_values_supported": ["PS256", "ES256"],
    }


@app.get("/.well-known/jwks.json")
async def get_jwks():
    jwks = auth.create_jwks(conf.JWT_SIGNING_KEY)
    return jwks


# Custom OpenAPI schema configuration
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Perseus Demo Authentication Server",
        version="1.0.0",
        description="Perseus Demo Authentication Server",
        routes=app.routes,
    )
    # Set the OpenAPI URL to the root domain
    openapi_schema["servers"] = [{"url": conf.API_DOMAIN}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi  # type: ignore
