import json
import datetime
from typing import Annotated

# import x509

from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from starlette.requests import Request
from ib1 import directory
from mangum import Mangum

from . import models
from . import auth
from . import conf
from . import provenance
from .exceptions import CertificateError, AccessTokenValidatorError
from .logger import get_logger


DEMO_METER_ID = "S018011012261305588165"
DEMO_DATA_SOURCE_LOCATION = "SW8"
logger = get_logger()


security = HTTPBearer(auto_error=False)


def require_mtls_and_token(
    request: Request,
    token: HTTPAuthorizationCredentials = Depends(security),
    x_amzn_mtls_clientcert_leaf: Annotated[str | None, Header()] = None,
    x_fapi_interaction_id: Annotated[str | None, Header()] = None,
) -> tuple[dict, dict, object]:
    """
    Dependency function that validates MTLS certificate and bearer token.
    Returns tuple of (cert_pem, decoded_token_dict, headers_dict, cert_object).
    Raises HTTPException if validation fails.
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
        logger.warning("No client certificate found in request")
        raise HTTPException(
            status_code=401,
            detail="Client certificate required",
        )

    cert = directory.parse_cert(cert_pem)
    logger.info(
        "Parsed certificate subject: %s", directory.extensions.decode_application(cert)
    )
    try:
        directory.require_role(
            conf.PROVIDER_ROLE,
            cert,
        )
    except CertificateError as e:
        raise HTTPException(
            status_code=401,
            detail=str(e),
        )
    if token and token.credentials:
        # TODO don't use instrospection, check the token signature
        # And check the certificate binding
        try:
            decoded, headers = auth.check_token(
                cert_pem,
                token.credentials,
                x_fapi_interaction_id,
            )
            logger.info("Token validated successfully for sub %s", decoded.get("sub"))
        except AccessTokenValidatorError as e:
            logger.warning("Token validation failed: %s", e)
            raise HTTPException(status_code=401, detail=str(e))
    else:
        logger.warning("No bearer token provided")
        raise HTTPException(status_code=401, detail="No token provided")

    return decoded, headers, cert


app = FastAPI(
    docs_url="/api-docs",
    title="Perseus Energy Demo Resource API",
    root_path=conf.OPEN_API_ROOT,
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


@app.get("/datasources", response_model=models.Datasources)
def datasources(
    auth_result: tuple[str, dict, dict, object] = Depends(require_mtls_and_token),
) -> dict:
    return {
        "data": [
            {
                "id": DEMO_METER_ID,
                "type": "electricity",
                "location": {"ukPostcodeOutcode": DEMO_DATA_SOURCE_LOCATION},
                "availableMeasures": ["import", "export"],
            }
        ]
    }


@app.get("/datasources/{id}/{measure}", response_model=models.MeterData)
def consumption(
    id: str,
    measure: str,
    from_date: datetime.date = Query(alias="from"),
    to_date: datetime.date = Query(alias="to"),
    auth_result: tuple[str, dict, dict, object] = Depends(require_mtls_and_token),
):
    if id != DEMO_METER_ID:
        raise HTTPException(status_code=404, detail="Meter not found")
    _, decoded, headers, cert = auth_result
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
        service_url=f"https://{conf.API_DOMAIN}/datasources/{id}/{measure}",
        fapi_id=headers["x-fapi-interaction-id"],
        cap_member=directory.extensions.decode_application(cert),
    )
    with open(f"{conf.ROOT_DIR}/data/sample_data.json") as f:
        data = json.load(f)
    logger.info("Returning data and provenance for %s", decoded["sub"])
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
        description="Perseus Demo EDP",
        routes=app.routes,
    )
    # Set the OpenAPI URL to the root domain
    openapi_schema["servers"] = [{"url": conf.API_DOMAIN}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi  # type: ignore

# Create Lambda handler
handler = Mangum(app)
