import json
import os
import datetime
from typing import Annotated


from fastapi import FastAPI, HTTPException, Response, Depends, Header, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

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
    x_amzn_mtls_clientcert: Annotated[str | None, Header()] = None,
    x_fapi_interaction_id: Annotated[str | None, Header()] = None,
):
    if not x_amzn_mtls_clientcert:
        raise HTTPException(
            status_code=401,
            detail="Client certificate required",
        )
    cert = directory.parse_cert(x_amzn_mtls_clientcert)
    try:
        directory.require_role(
            "https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting",
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
            _, headers = auth.check_token(
                x_amzn_mtls_clientcert,
                token.credentials,
                conf.CATALOG_ENTRY_URL,
                x_fapi_interaction_id,
            )
        except AccessTokenValidatorError as e:
            raise HTTPException(status_code=401, detail=str(e))
        else:
            for key, value in headers.items():
                response.headers[key] = value
    else:
        raise HTTPException(status_code=401, detail="No token provided")
    # Create a new provenance record
    record = provenance.create_provenance_records(
        from_date,
        to_date,
        fapi_id=headers["x-fapi-interaction-id"],
        cap_member=directory.extensions.decode_application(cert),
    )
    with open(f"{conf.ROOT_DIR}/data/sample_data.json") as f:
        data = json.load(f)
    return {"data": data, "provenance": record}
