from typing import Annotated
import json
import os
import uuid
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from cryptography import x509
from fastapi import (
    FastAPI,
    Depends,
    Header,
    Request,
    status,
    Form,
)
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, Response
from ib1 import directory
from . import models
from . import conf
from . import store
from . import auth
from . import openapi
from . import permissions
from . import evidence
from . import messaging
from . import hydra
from .exceptions import (
    AccessTokenDecodingError,
    OAuthError,
    PermissionRevocationError,
)
from .logger import get_logger

logger = get_logger()

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


app = FastAPI(
    docs_url="/api-docs",
    title="Perseus Demo Authentication Server",
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


# Documented on the four endpoints that answer in the RFC 6749 error shape
OAUTH_ERROR_RESPONSES: dict = {
    400: {"model": models.OAuthErrorResponse, "description": "OAuth2 error"},
    401: {
        "model": models.OAuthErrorResponse,
        "description": "Client authentication failed",
    },
    502: {
        "model": models.OAuthErrorResponse,
        "description": "Authorization server error",
    },
}


def correlation_id() -> str:
    """
    An identifier a caller can quote when reporting a server side failure.
    """
    return uuid.uuid4().hex[:12]


@app.exception_handler(OAuthError)
async def oauth_error_handler(request: Request, exc: OAuthError) -> JSONResponse:
    """
    Render OAuth2 errors in the RFC 6749 section 5.2 shape.

    FastAPI's HTTPException cannot produce this, it always renders
    {"detail": ...}.
    """
    body = exc.body()
    if exc.status_code >= 500:
        reference = correlation_id()
        body["correlation_id"] = reference
        logger.error(
            f"{exc.error} on {request.url.path}, correlation {reference}"
        )
    return JSONResponse(status_code=exc.status_code, content=body)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    Answer a validation failure in the same shape as every other error.

    FastAPI's default is a 422 carrying Pydantic's loc/msg/type list. RFC 6749
    calls a malformed request invalid_request and a 400, so the failing
    parameters are named in the description instead.
    """
    parameters = sorted(
        {
            ".".join(str(part) for part in error["loc"][1:]) or "body"
            for error in exc.errors()
        }
    )
    return JSONResponse(
        status_code=400,
        content={
            "error": "invalid_request",
            "error_description": (
                "Invalid or missing parameters: " + ", ".join(parameters)
            ),
        },
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch everything else, so infrastructure failures are reportable.

    Redis, DynamoDB and SSM failures all reached the caller as a bare
    500 Internal Server Error with no body and nothing to quote.
    """
    reference = correlation_id()
    logger.exception(
        f"Unhandled error on {request.url.path}, correlation {reference}"
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "server_error",
            "error_description": hydra.UPSTREAM_ERROR,
            "correlation_id": reference,
        },
    )


@app.get("/")
async def docs() -> dict:
    return {"docs": "/api-docs"}


def parse_client_cert(client_certificate: str) -> x509.Certificate:
    """
    Parse a client certificate, rejecting the request if it cannot be read
    """
    try:
        return directory.parse_cert(client_certificate)
    except directory.CertificateInvalidError as e:
        logger.warning(f"Client certificate could not be parsed: {e}")
        raise OAuthError(status.HTTP_401_UNAUTHORIZED, "invalid_client", str(e))


def client_id_from_cert(client_cert: x509.Certificate) -> str:
    """
    Read the application ID from a client certificate, rejecting the request if
    the certificate does not carry one
    """
    try:
        return directory.extensions.decode_application(client_cert)
    except directory.CertificateExtensionError as e:
        logger.warning(f"Client certificate is missing application information: {e}")
        raise OAuthError(status.HTTP_401_UNAUTHORIZED, "invalid_client", str(e))


@app.post(
    "/api/v1/par",
    response_model=models.PushedAuthorizationResponse,
    status_code=201,
    responses=OAUTH_ERROR_RESPONSES,
    openapi_extra={"security": [{"mtls": []}]},
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
        raise OAuthError(
            status.HTTP_401_UNAUTHORIZED,
            "invalid_client",
            "Client certificate required",
        )

    client_cert = parse_client_cert(x_amzn_mtls_clientcert_leaf)
    client_id = client_id_from_cert(client_cert)
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
    token = store.get_token()
    store.store_request(token, parameters)
    store.store_callback_url(parameters["state"], redirect_uri)
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
        raise OAuthError(
            status.HTTP_400_BAD_REQUEST, "invalid_request", "Request URI required"
        )
    # Retrieve PAR data from Redis
    token = request_uri.split(":")[-1]
    par_request = store.get_request(token)
    if not par_request:
        # RFC 9101 section 6.2 registers invalid_request_uri for exactly this
        raise OAuthError(
            status.HTTP_400_BAD_REQUEST,
            "invalid_request_uri",
            "Request URI does not exist or has expired",
        )

    authorization_url = (
        f"{conf.ORY_AUTHORIZATION_ENDPOINT}?"
        f"client_id={conf.ORY_CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={conf.CALLBACK_URL}&"
        f"scope={par_request['scope']}&"
        f"code_challenge={par_request['code_challenge']}&"
        f"code_challenge_method=S256&"
        f"request={json.dumps(par_request)}&"
        f"state={par_request['state']}"
    )
    logger.info(f"Redirecting to {authorization_url}")
    # Redirect the user to the authorization URL
    return Response(status_code=302, headers={"Location": authorization_url})


@app.get("/api/v1/callback")
async def callback(request: Request):
    """
    Callback proxy endpoint

    Hydra redirects here after login/consent. We look up the client's
    original callback URL from Redis (keyed by state) and forward the
    user there with all query parameters preserved.
    """
    params = dict(request.query_params)
    state = params.get("state")
    if not state:
        raise OAuthError(
            status.HTTP_400_BAD_REQUEST, "invalid_request", "Missing state parameter"
        )

    original_url = store.get_callback_url(state)
    if not original_url:
        raise OAuthError(
            status.HTTP_400_BAD_REQUEST,
            "invalid_request",
            "Callback URL not found or expired for this state",
        )

    parsed = urlparse(original_url)
    existing_params = parse_qs(parsed.query, keep_blank_values=True)
    # Flatten single-value lists from parse_qs
    merged = {k: v[0] if len(v) == 1 else v for k, v in existing_params.items()}
    merged.update(params)
    new_query = urlencode(merged, doseq=True)
    redirect_url = urlunparse(parsed._replace(query=new_query))

    return Response(status_code=302, headers={"Location": redirect_url})


async def parsed_client_cert(
    x_amzn_mtls_clientcert_leaf: str | None = Header(None),
) -> x509.Certificate:
    """
    Parse the client certificate from the request header
    """
    if x_amzn_mtls_clientcert_leaf is None:
        raise OAuthError(401, "invalid_client", "Client certificate required")
    client_cert = parse_client_cert(x_amzn_mtls_clientcert_leaf)
    try:
        directory.require_role(
            conf.PROVIDER_ROLE,
            client_cert,
        )
    except (directory.CertificateRoleError, directory.CertificateExtensionError) as e:
        logger.warning(f"Client certificate role check failed: {e}")
        raise OAuthError(401, "invalid_client", str(e))
    return client_cert


@app.post(
    "/api/v1/authorize/token",
    response_model=models.TokenResponse,
    responses=OAUTH_ERROR_RESPONSES,
    openapi_extra={"security": [{"mtls": []}]},
)
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
            raise OAuthError(400, "invalid_request", "Missing required parameters")

        payload = {
            "grant_type": grant_type,
            "code": code,
            "redirect_uri": conf.CALLBACK_URL,
            "client_id": conf.ORY_CLIENT_ID,
            "code_verifier": code_verifier,
        }
    elif grant_type == "refresh_token":
        logger.info("Refresh token flow")
        if not refresh_token:
            raise OAuthError(400, "invalid_request", "Missing refresh token")

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": conf.ORY_CLIENT_ID,
        }
    else:
        raise OAuthError(400, "unsupported_grant_type", "Invalid grant type")

    result = hydra.request_token(payload)
    # Bind the token to the client by setting client_id from the certificate
    try:
        enhanced_token = auth.create_enhanced_access_token(
            result["access_token"],
            client_cert,
            f"{conf.ORY_URL}/.well-known/jwks.json",
        )
    except AccessTokenDecodingError as e:
        reference = permissions.token_reference(result.get("access_token", ""))
        if "expired" in str(e).lower():
            # A token Hydra has just issued cannot legitimately be expired
            logger.error(
                f"Ory Hydra issued an already expired token, ref {reference}. "
                "Check clock skew between this service and Ory."
            )
        else:
            logger.exception(
                f"Could not decode the access token from Ory Hydra, ref {reference}"
            )
        raise OAuthError(
            status.HTTP_502_BAD_GATEWAY, "server_error", hydra.UPSTREAM_ERROR
        )
    except directory.CertificateExtensionError as e:
        logger.warning(f"Client certificate is missing application information: {e}")
        raise OAuthError(status.HTTP_401_UNAUTHORIZED, "invalid_client", str(e))
    encoded_token = auth.encode_jwt(
        enhanced_token,
    )
    permissions.store_permission(enhanced_token, result.get("refresh_token"))
    logger.info(
        f"Issued token for {enhanced_token.get('client_id')}, grant {grant_type}, "
        f"ref {permissions.token_reference(encoded_token)}, "
        f"expires {enhanced_token.get('exp')}"
    )
    return models.TokenResponse(
        access_token=encoded_token,
        refresh_token=result.get("refresh_token"),
    )


@app.post(
    "/api/v1/permissions",
    dependencies=[Depends(parsed_client_cert)],
    responses={**OAUTH_ERROR_RESPONSES, 404: {"model": models.OAuthErrorResponse}},
    openapi_extra={"security": [{"mtls": []}]},
)
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
        logger.warning(
            f"No permissions found for token {permissions.token_reference(token)}"
        )
        # Not an OAuth2 condition, so there is no registered code that fits.
        # invalid_request is the closest, and the status carries the meaning.
        raise OAuthError(
            status.HTTP_404_NOT_FOUND,
            "invalid_request",
            "No permissions found for token",
        )
    return {"permissions": permissions_data}


@app.post(
    "/api/v1/authorize/revoke",
    responses=OAUTH_ERROR_RESPONSES,
    openapi_extra={"security": [{"mtls": []}]},
)
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
    - Sends a message to the client application to notify them of the revocation
    __nb__ A production implementation must have robust error handling and retries for the client notification
    """
    # Prepare revocation request to Hydra
    payload = {"token": token, "token_type_hint": token_type_hint}

    try:
        revoked_permission = permissions.revoke_permission(token)
    except PermissionRevocationError as e:
        raise OAuthError(400, "invalid_grant", str(e))

    hydra.revoke_token(payload)

    # Send revocation message to the client application
    # For demo purposes we do allow this to fail without impacting the revocation response
    # but in a production system you would want to implement retries and error handling here
    try:
        messaging.send_revocation_message(revoked_permission)
    except Exception as e:
        # Log error but don't fail the revocation request
        logger.exception(
            f"Failed to send revocation message for client {revoked_permission.client}: {str(e)}"
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
        description=openapi.API_DESCRIPTION,
        routes=app.routes,
    )
    # Set the OpenAPI URL to the root domain
    openapi_schema["servers"] = [{"url": conf.API_DOMAIN}]
    # Inject the FAPI security schemes (mTLS + OAuth2) that FastAPI cannot infer
    openapi.add_fapi_security_schemes(openapi_schema)
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi  # type: ignore
