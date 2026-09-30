"""
One structured log line for every request, naming the client certificate that
made it, the route it reached and how it ended.

The line carries "event": "request", so a Logs Insights query can select these
from everything else with `filter event = "request"`. Code handling a request
adds fields to it with `record()`, for example the grant type or why a request
was refused. Nothing secret goes in: tokens are named by token_reference only.
"""

import contextvars
import datetime
import time
import uuid

from cryptography.hazmat.primitives import hashes
from ib1 import directory
from starlette.datastructures import Headers, MutableHeaders

from . import conf
from .logger import get_logger

logger = get_logger()

CERTIFICATE_HEADER = "x-amzn-mtls-clientcert-leaf"

# Load balancer health checks would otherwise dominate the logs
HEALTH_CHECK_AGENT = "ELB-HealthChecker"
QUIET_PREFIXES = ("/static",)

_fields: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "audit_fields", default=None
)


def record(**fields) -> None:
    """
    Add fields to the audit line for the request being handled. Fields that are
    None are left out. Outside a request this does nothing.
    """
    current = _fields.get()
    if current is not None:
        current.update(
            (key, value) for key, value in fields.items() if value is not None
        )


def request_id() -> str:
    """
    A short identifier for one request, also given to the caller as
    X-Request-Id and, on a server error, as the correlation_id.
    """
    return uuid.uuid4().hex[:12]


def certificate_identity(pem: str | None) -> dict:
    """
    Describe a client certificate for the logs. Never raises: a certificate that
    cannot be read is refused by the endpoint, and the audit line records that.
    """
    if not pem:
        return {}
    try:
        cert = directory.parse_cert(pem)
    except Exception:
        return {"client_certificate": "unreadable"}
    not_after = cert.not_valid_after_utc
    identity = {
        "client_subject": cert.subject.rfc4514_string(),
        "client_issuer": cert.issuer.rfc4514_string(),
        # Hex, as the load balancer's connection logs give it
        "client_serial": format(cert.serial_number, "X"),
        "client_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "client_not_after": not_after.isoformat(),
        "client_days_to_expiry": (
            not_after - datetime.datetime.now(datetime.timezone.utc)
        ).days,
    }
    for key, decode in (
        ("client_application", directory.extensions.decode_application),
        ("client_member", directory.extensions.decode_member),
        ("client_roles", directory.extensions.decode_roles),
    ):
        try:
            identity[key] = decode(cert)
        except Exception:
            pass
    return identity


def certificate_pem(scope) -> str | None:
    """
    The client certificate as the load balancer forwards it, or from the Lambda
    event, where require_mtls_and_token also looks
    """
    pem = Headers(scope=scope).get(CERTIFICATE_HEADER)
    if pem:
        return pem
    return (
        scope.get("aws.event", {})
        .get("requestContext", {})
        .get("authentication", {})
        .get("clientCert", {})
        .get("clientCertPem")
    )


def outcome(status: int) -> str:
    if status >= 500:
        return "server_error"
    if status >= 400:
        return "client_error"
    return "success"


class AuditMiddleware:
    """
    Write the audit line once the response has started, or once an unhandled
    exception has passed through on its way to the server error handler.
    """

    def __init__(self, app, service: str):
        self.app = app
        self.service = service

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        reference = request_id()
        fields: dict = {"request_id": reference}
        # The server error handler runs outside this middleware, and reads the
        # request id from here to use as the correlation id
        scope.setdefault("state", {})["audit"] = fields
        token = _fields.set(fields)
        started = time.perf_counter()
        status = 500

        async def send_with_id(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                MutableHeaders(scope=message).append("X-Request-Id", reference)
            await send(message)

        try:
            with logger.contextualize(request_id=reference):
                await self.app(scope, receive, send_with_id)
        except Exception:
            status = 500
            fields.setdefault("error", "server_error")
            fields.setdefault("correlation_id", reference)
            raise
        finally:
            _fields.reset(token)
            self.write(scope, fields, status, started)

    def write(self, scope, fields: dict, status: int, started: float) -> None:
        headers = Headers(scope=scope)
        path = scope.get("path", "")
        user_agent = headers.get("user-agent", "")
        if user_agent.startswith(HEALTH_CHECK_AGENT) or path.startswith(QUIET_PREFIXES):
            return
        route = getattr(scope.get("route"), "path", None)
        forwarded = headers.get("x-forwarded-for")
        client = scope.get("client")
        entry = {
            "event": "request",
            "service": self.service,
            "env": conf.ENV,
            "method": scope.get("method"),
            # The template, so every call to one endpoint groups together
            "route": route or "unmatched",
            "path": path,
            "host": headers.get("host"),
            "status": status,
            "outcome": outcome(status),
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "source_ip": (
                forwarded.split(",")[0].strip()
                if forwarded
                else (client[0] if client else None)
            ),
            "user_agent": user_agent or None,
            **certificate_identity(certificate_pem(scope)),
            **fields,
        }
        entry = {key: value for key, value in entry.items() if value is not None}
        level = "INFO" if status < 400 else "WARNING"
        logger.bind(**entry).log(level, f"{entry['method']} {path} {status}")
