import json
import datetime
from typing import Annotated

# import x509

from fastapi import FastAPI, HTTPException, Response, Depends, Header, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi

from . import models
from . import auth
from . import conf
from . import provenance
from .exceptions import CertificateError, AccessTokenValidatorError

from ib1 import directory


security = HTTPBearer(auto_error=False)


app = FastAPI(
    docs_url="/api-docs",
    title="Perseus Energy Demo Resource API",
    root_path=conf.OPEN_API_ROOT,
)


@app.get("/", response_model=dict)
def root():
    return {"urls": ["/datasources", "/datasources/{id}/{measure}"]}


@app.get("/datasources", response_model=models.Datasources)
def datasources() -> dict:
    return {
        "data": [
            {
                "id": "abcd1234",
                "type": "Electricity",
                "availableMeasures": ["Import"],
            },
        ]
    }


@app.get("/datasources/{id}/{measure}", response_model=models.MeterData)
def consumption(
    id: str,
    measure: str,
    response: Response,
    from_date: datetime.date = Query(alias="from"),
    to_date: datetime.date = Query(alias="to"),
    token: HTTPAuthorizationCredentials = Depends(security),
    x_amzn_mtls_clientcert_leaf: Annotated[str | None, Header()] = None,
    x_fapi_interaction_id: Annotated[str | None, Header()] = None,
):
    if not x_amzn_mtls_clientcert_leaf:
        raise HTTPException(
            status_code=401,
            detail="Client certificate required",
        )
    cert = directory.parse_cert(x_amzn_mtls_clientcert_leaf)
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
                x_amzn_mtls_clientcert_leaf,
                token.credentials,
                x_fapi_interaction_id,
            )
        except AccessTokenValidatorError as e:
            raise HTTPException(status_code=401, detail=str(e))
    else:
        raise HTTPException(status_code=401, detail="No token provided")
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
        service_url=f"https://perseus-demo-energy.ib1.org/consumption/datasources/{id}/{measure}",
        fapi_id=headers["x-fapi-interaction-id"],
        cap_member=directory.extensions.decode_application(cert),
    )
    with open(f"{conf.ROOT_DIR}/data/sample_data.json") as f:
        data = json.load(f)
    return {"data": data, "provenance": record}


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
