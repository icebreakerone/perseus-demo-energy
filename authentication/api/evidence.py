""" "
User readable permissions record:

Permissions data: {
  permissions: {
    oauthIssuer: 'https://localhost:8000',
    client: 'https://registry.core.pilot.trust.ib1.org/application/edp-demo',
    license: 'https://registry.core.pilot.trust.ib1.org/scheme/perseus/license/energy-consumption-data/2024-12-05',
    account: 'd6fd6e1c-a10e-40d8-aa2b-9606f3d34d3c',
    lastGranted: '2025-04-28T10:23:02Z',
    expires: '2025-04-28T11:23:02Z',
    refreshToken: 'ory_rt_0xCL9EL8lyXSPMIJt52JXcRNpEOop8NLm5iW1pZjkGE.psgPleEHnKnSSSctrlHIIB-tpVPfIi1kC9xV6q_iOTI',
    revoked: null,
    dataAvailableFrom: '2025-04-28T10:23:03.194844Z',
    tokenIssuedAt: '2025-04-28T10:23:02Z',
    tokenExpires: '2025-04-28T11:23:02Z'
  }

"""

# route_homepage.py
import os

from fastapi import APIRouter
from fastapi import Request
from fastapi.templating import Jinja2Templates
from . import permissions

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=f"{ROOT_DIR}/templates/")
html_router = APIRouter()


@html_router.get("/test")
async def test(request: Request):
    return {"message": "Hello World"}


@html_router.get("/evidence/{evidence_id:str}")
async def evidence(request: Request, evidence_id: str):
    permission = permissions.get_permission_by_evidence_id(evidence_id)
    if not permission:
        return templates.TemplateResponse(
            "error.html",
            {
                "message": "Permission not found",
                "request": request,
            },
        )

    return templates.TemplateResponse(
        "evidence.html",
        {
            "permission": permission,
            "request": request,
        },
    )
