from typing import Annotated
from contextlib import asynccontextmanager
import json
import os
import threading

from cryptography import x509
from fastapi import (
    FastAPI,
    Depends,
    Header,
    HTTPException,
    status,
    Form,
)
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import Response
from ib1 import directory
from . import models
from . import conf
from . import par
from . import auth
from . import permissions
from . import evidence
from . import messaging
from .exceptions import PermissionRevocationError
from .logger import get_logger

logger = get_logger()

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage background tasks for the FastAPI application."""
    # Startup: Start message queue worker in background thread
    logger.info("Starting message queue worker...")
    worker_thread = threading.Thread(
        target=messaging.process_message_queue,
        args=("main-worker",),
        daemon=True,
        name="message-queue-worker",
    )
    worker_thread.start()
    logger.info("Message queue worker started")

    yield

    # Shutdown: Worker thread will be terminated as daemon
    logger.info("Shutting down message queue worker...")


app = FastAPI(
    docs_url="/api-docs",
    title="Perseus Demo Authentication Server",
    lifespan=lifespan,
    # root_path=conf.OPEN_API_ROOT,
)

app.include_router(evidence.html_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=f"{ROOT_DIR}/static"), name="static")


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


async def parsed_client_cert(
    x_amzn_mtls_clientcert_leaf: str | None = Header(None),
) -> x509.Certificate:
    """
    Parse the client certificate from the request header
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
    return client_cert


@app.post("/api/v1/authorize/token", response_model=models.TokenResponse)
async def token(
    grant_type: Annotated[str, Form()],
    redirect_uri: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    code: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
    client_cert: x509.Certificate = Depends(parsed_client_cert),
) -> models.TokenResponse:
    """
    Token issuing endpoint

    We use the Ory Hydra endpoint to issue the token and validate authorisation code flow
    but due to missing features in Ory Hydra authorisation code flow we need to generate
    our own id_token, and add client certificate details to the token
    """

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
        client_cert,
        f"{conf.ORY_URL}/.well-known/jwks.json",
    )
    encoded_token = auth.encode_jwt(
        enhanced_token,
    )
    # permissions.store_permission(
    logger.info(f"Enhanced token: {enhanced_token}")
    permissions.store_permission(enhanced_token, result.get("refresh_token"))
    return models.TokenResponse(
        access_token=encoded_token,
        refresh_token=result.get("refresh_token"),
    )


@app.post("/api/v1/permissions", dependencies=[Depends(parsed_client_cert)])
async def get_permissions(
    token: str = Form(...),
):
    """
    Permissions endpoint

    - Requires mTLS authentication (client certificate validation)
    - Returns the permissions for the client
    """

    # Get permissions from Redis
    permissions_data = permissions.get_permission_by_token(token)
    if permissions_data is None:
        logger.error(f"No permissions found for {token}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No permissions found for token",
        )
    return {"permissions": permissions_data}


@app.post("/api/v1/authorize/revoke")
async def revoke_token(
    token: str = Form(...),
    token_type_hint: str = Form(None),
    client_cert: x509.Certificate = Depends(parsed_client_cert),
):
    """
    Token revocation endpoint

    - Requires mTLS authentication (client certificate validation)
    - Calls Ory Hydra's token revocation endpoint
    - Supports both access and refresh token revocation
    - Marks stored permission as revoked
    - Queues a message for asynchronous delivery to the client application to notify them of the revocation
    """
    # Prepare revocation request to Hydra
    payload = {"token": token, "token_type_hint": token_type_hint}
    session = auth.get_session()

    try:
        revoked_permission = permissions.revoke_permission(token)
    except PermissionRevocationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if revoked_permission is None:
        raise HTTPException(status_code=400, detail="Failed to revoke permission")

    response = session.post(
        f"{conf.ORY_URL}/oauth2/revoke",
        data=payload,
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    # Queue message for asynchronous delivery to the client application
    try:
        message_id = messaging.enqueue_revocation_message(revoked_permission)
        logger.info(
            f"Enqueued revocation message {message_id} for client {revoked_permission.client}"
        )
    except Exception as e:
        # Log error but don't fail the revocation request
        logger.error(
            f"Failed to enqueue revocation message for client {revoked_permission.client}: {str(e)}",
            exc_info=True,
        )

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
        "permissions_endpoint": f"{conf.ISSUER_URL}/api/v1/permissions",
        "jwks_uri": f"{conf.UNPROTECTED_URL}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "authorization_endpoint_auth_methods_supported": ["tls_client_auth"],
        "token_endpoint_auth_methods_supported": ["tls_client_auth"],
        "require_pushed_authorization_requests": True,
        "code_challenge_methods_supported": ["S256"],
        "mtls_endpoint_aliases": {
            "authorization_endpoint": f"{conf.UNPROTECTED_URL}/api/v1/authorize",
            "pushed_authorization_request_endpoint": f"{conf.ISSUER_URL}/api/v1/par",
            "token_endpoint": f"{conf.ISSUER_URL}/api/v1/authorize/token",
            "revocation_endpoint": f"{conf.ISSUER_URL}/api/v1/authorize/revoke",
            "permissions_endpoint": f"{conf.ISSUER_URL}/api/v1/permissions",
        },
        "use_mtls_endpoint_aliases": True,
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
