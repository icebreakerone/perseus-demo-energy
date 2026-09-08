import datetime
import uuid
from typing import Annotated

# import x509

from fastapi import FastAPI, Depends, Header, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from ib1 import directory
from mangum import Mangum

from . import models
from . import auth
from . import conf
from . import consumption as consumption_data
from . import openapi
from . import provenance
from .exceptions import ApiError, AccessTokenValidatorError
from .logger import get_logger


DEMO_METER_ID = "S018011012261305588165"
DEMO_DATA_SOURCE_LOCATION = "SW8"

# Compression is what makes a year of half-hourly readings fit in the 1MB a load
# balancer will carry back from a Lambda. A caller that will not take a compressed
# response is held to a window that fits without it.
UNCOMPRESSED_WINDOW = datetime.timedelta(days=60)

# The data sources this demo serves, keyed by the id /datasources advertises.
DATA_SOURCES: dict[str, dict] = {
    DEMO_METER_ID: {
        "id": DEMO_METER_ID,
        "type": models.EnergyType.ELECTRICITY,
        "location": {"ukPostcodeOutcode": DEMO_DATA_SOURCE_LOCATION},
        "availableMeasures": list(models.Measure),
    },
}

logger = get_logger()


security = HTTPBearer(auto_error=False)


def require_mtls_and_token(
    request: Request,
    token: HTTPAuthorizationCredentials = Depends(security),
    x_amzn_mtls_clientcert_leaf: Annotated[str | None, Header()] = None,
) -> tuple[dict, dict, object]:
    """
    Dependency function that validates MTLS certificate and bearer token.
    Returns tuple of (cert_pem, decoded_token_dict, headers_dict, cert_object).
    Raises ApiError if validation fails.
    """
    cert_pem = x_amzn_mtls_clientcert_leaf
    if not cert_pem:
        aws_event = request.scope.get("aws.event", {})
        cert_context = (
            aws_event.get("requestContext", {})
            .get("authentication", {})
            .get("clientCert", {})
        )
        cert_pem = cert_context.get("clientCertPem")
        logger.info("Loaded certificate from requestContext.authentication")
    else:
        logger.info("Loaded certificate from x_amzn_mtls_clientcert_leaf header")

    if not cert_pem:
        # Defence in depth. In production the ALB listener runs mutual
        # authentication in "verify" mode, so a certificate-less connection is
        # refused before it reaches us. This is reachable locally, where nginx
        # uses ssl_verify_client optional, and would be if the app were ever
        # exposed without the ALB in front of it.
        logger.warning("No client certificate found in request")
        raise ApiError(401, "invalid_token", "Client certificate required")

    try:
        cert = directory.parse_cert(cert_pem)
        logger.info(
            f"Parsed certificate subject: "
            f"{directory.extensions.decode_application(cert)}"
        )
    except directory.CertificateInvalidError as e:
        logger.warning(f"Client certificate could not be parsed: {e}")
        raise ApiError(401, "invalid_token", str(e))
    except directory.CertificateExtensionError as e:
        logger.warning(f"Client certificate is missing required extensions: {e}")
        raise ApiError(401, "invalid_token", str(e))
    try:
        directory.require_role(
            conf.PROVIDER_ROLE,
            cert,
        )
    except (directory.CertificateRoleError, directory.CertificateExtensionError) as e:
        logger.warning(f"Client certificate role check failed: {e}")
        raise ApiError(401, "invalid_token", str(e))
    if token and token.credentials:
        # TODO don't use instrospection, check the token signature
        # And check the certificate binding
        try:
            decoded, headers = auth.check_token(
                cert_pem,
                token.credentials,
            )
            logger.info(f"Token validated successfully for sub {decoded.get('sub')}")
        except AccessTokenValidatorError as e:
            logger.warning(f"Token validation failed: {e}")
            raise ApiError(401, "invalid_token", str(e))
    else:
        # RFC 6750 section 3: no credentials presented, so the challenge
        # carries no error code
        logger.warning("No bearer token provided")
        raise ApiError(
            401, "invalid_token", "No token provided", include_code_in_header=False
        )

    return decoded, headers, cert


app = FastAPI(
    docs_url="/api-docs",
    title="Perseus Energy Demo Resource API",
    root_path=conf.OPEN_API_ROOT,
)

# A year of half-hourly readings is around 3.5MB of JSON, well past the 1MB an ALB
# will carry back from a Lambda, but it is repetitive and compresses to a fraction
# of that. Mangum base64-encodes the compressed body, since gzip's leading bytes are
# not valid UTF-8, and the load balancer unwraps it.
app.add_middleware(GZipMiddleware, minimum_size=1000)

API_ERROR_RESPONSES: dict = {
    400: {"model": models.ApiErrorResponse, "description": "Malformed request"},
    401: {
        "model": models.ApiErrorResponse,
        "description": "Certificate or token rejected",
    },
    404: {"model": models.ApiErrorResponse, "description": "Not found"},
}


def correlation_id() -> str:
    """
    An identifier a caller can quote when reporting a server side failure.
    """
    return uuid.uuid4().hex[:12]


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    """
    Render errors with an RFC 6750 code, and a challenge on a 401.
    """
    headers = {}
    challenge = exc.header()
    if challenge:
        headers["WWW-Authenticate"] = challenge
    return JSONResponse(
        status_code=exc.status_code, content=exc.body(), headers=headers
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    Answer a validation failure in the same shape as every other error.
    """
    problems = sorted(
        {
            f"{'.'.join(str(part) for part in error['loc'][1:]) or 'body'}: "
            f"{error['msg']}"
            for error in exc.errors()
        }
    )
    return JSONResponse(
        status_code=400,
        content={
            "error": "invalid_request",
            "error_description": "Invalid or missing parameters. " + "; ".join(problems),
        },
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch everything else, so infrastructure failures are reportable.
    """
    reference = correlation_id()
    logger.exception(
        f"Unhandled error on {request.url.path}, correlation {reference}"
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "server_error",
            "error_description": "Server error",
            "correlation_id": reference,
        },
    )


@app.get("/", response_model=dict)
def root():
    return {
        "urls": ["/datasources", "/datasources/{id}/{measure}"],
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_json": "/openapi.json",
        },
    }


@app.get(
    "/datasources",
    response_model=models.Datasources,
    responses=API_ERROR_RESPONSES,
)
def datasources(
    auth_result: tuple[dict, dict, object] = Depends(require_mtls_and_token),
) -> dict:
    return {"data": list(DATA_SOURCES.values())}


def _resolve_window(
    request: Request,
    from_date: datetime.datetime,
    to_date: datetime.datetime | None,
) -> tuple[datetime.datetime, datetime.datetime]:
    """
    Settle the window a caller asked for, or say why it cannot be served.

    `to` is optional and means "now", as the registry API declares. Both edges snap
    back to the half hour containing them, so a caller passing 09:47 gets the 09:30
    reading rather than silently losing it.
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    # A caller may send a bare date. Read anything without a zone as UTC rather
    # than guessing at the caller's.
    if from_date.tzinfo is None:
        from_date = from_date.replace(tzinfo=datetime.timezone.utc)
    if to_date is None:
        to_date = now
    elif to_date.tzinfo is None:
        to_date = to_date.replace(tzinfo=datetime.timezone.utc)

    from_date = consumption_data.align(from_date)
    to_date = consumption_data.align(to_date)

    if to_date <= from_date:
        raise ApiError(
            400, "invalid_request", "The 'to' date must be after the 'from' date"
        )
    if to_date - from_date > consumption_data.MAX_WINDOW:
        raise ApiError(
            400,
            "invalid_request",
            f"At most {consumption_data.MAX_WINDOW.days} days can be requested at "
            f"once, which covers the previous 12 complete months",
        )

    # Without compression a long window exceeds what a load balancer will carry
    # back from a Lambda, so say so rather than failing at the edge.
    accepts_gzip = "gzip" in request.headers.get("accept-encoding", "").lower()
    if not accepts_gzip and to_date - from_date > UNCOMPRESSED_WINDOW:
        raise ApiError(
            400,
            "invalid_request",
            f"Windows longer than {UNCOMPRESSED_WINDOW.days} days are only served "
            f"compressed. Send 'Accept-Encoding: gzip'",
        )

    return from_date, to_date


@app.get(
    "/datasources/{id}/{measure}",
    response_model=models.MeterData,
    responses=API_ERROR_RESPONSES,
)
def consumption(
    request: Request,
    id: str,
    measure: models.Measure,
    from_date: datetime.datetime = Query(alias="from"),
    to_date: datetime.datetime | None = Query(alias="to", default=None),
    auth_result: tuple[dict, dict, object] = Depends(require_mtls_and_token),
):
    source = DATA_SOURCES.get(id)
    if source is None:
        # Not an RFC 6750 condition, so no registered code fits. The status
        # carries the meaning and no challenge is sent.
        raise ApiError(404, "not_found", "Meter not found")
    from_date, to_date = _resolve_window(request, from_date, to_date)
    decoded, _, cert = auth_result
    # Create a new provenance record
    permission_granted = datetime.datetime.now(datetime.timezone.utc)
    permission_expires = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(days=365)
    record = provenance.create_provenance_records(
        from_date=from_date,
        to_date=to_date,
        permission_expires=permission_expires,
        permission_granted=permission_granted,
        account=decoded["sub"],
        service_url=f"https://{conf.API_DOMAIN}/datasources/{id}/{measure.value}",
        cap_member=directory.extensions.decode_application(cert),
        # The record must name the license the user consented to, which is the
        # one granted on this token, not whichever this server prefers.
        license_url=auth.license_from_scopes(decoded.get("scp", [])),
    )
    data = consumption_data.readings(from_date, to_date, source["type"], measure)
    logger.info(
        f"Returning {len(data)} readings and provenance for {decoded['sub']}"
    )
    return {
        "data": data,
        "location": {"ukPostcodeOutcode": DEMO_DATA_SOURCE_LOCATION},
        "provenance": record,
    }


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Perseus Demo EDP",
        version="1.0.0",
        description=openapi.API_DESCRIPTION,
        routes=app.routes,
    )
    # Set the OpenAPI URL to the root domain
    openapi_schema["servers"] = [{"url": conf.API_DOMAIN}]
    # Inject the FAPI security schemes (mTLS + certificate-bound token) and
    # rewrite the auto-generated bearer requirement to the combined mTLS+token one.
    openapi.add_fapi_security_schemes(openapi_schema)
    openapi.apply_protected_security(openapi_schema)
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi  # type: ignore

# Create Lambda handler
handler = Mangum(app)
