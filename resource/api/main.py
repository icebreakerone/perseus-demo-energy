import json
import os
from typing import Annotated

from fastapi import FastAPI, HTTPException, Response, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Request

from . import models
from . import auth
from . import conf
from .exceptions import CertificateError, AccessTokenValidatorError

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

security = HTTPBearer(auto_error=False)


app = FastAPI(
    docs_url="/api-docs",
    title="Perseus Energy Demo Resource API",
    root_path=conf.OPEN_API_ROOT,
)


@app.get("/", response_model=dict)
def root():
    return {"urls": ["/api/v1/"]}


@app.get("/api/v1", response_model=dict)
def api_urls():
    return {"urls": ["/api/v1/consumption"]}


# @app.get("/api/v1/info")
@app.get("/api/v1/info")
def request_info(request: Request):
    """Return full details about the received request, including http and https headers
    Useful for testing and debugging
    """
    return {
        "request": {
            "headers": dict(request.headers),
            "method": request.method,
            "url": request.url,
            # "body": request.body().decode("utf-8"),
        },
        # "environ": str(request.environ),
    }


@app.get("/api/v1/consumption", response_model=models.MeterData)
def consumption(
    response: Response,
    token: HTTPAuthorizationCredentials = Depends(security),
    x_amzn_mtls_clientcert: Annotated[str | None, Header()] = None,
    x_fapi_interaction_id: Annotated[str | None, Header()] = None,
):
    if not x_amzn_mtls_clientcert:
        raise HTTPException(
            status_code=401,
            detail="Client certificate required",
        )
    try:
        auth.require_role(
            "https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting",
            x_amzn_mtls_clientcert,
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
    with open(f"{ROOT_DIR}/data/7_day_consumption.json") as f:
        data = json.load(f)
    return {"data": data}
