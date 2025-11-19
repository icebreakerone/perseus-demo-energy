"""
Lambda authorizer for HTTP API with mTLS.

This function:
- Reads the client certificate PEM from event.requestContext.authentication.clientCert.clientCertPem
  (HTTP API + Lambda authorizer v2 payload).
- Returns a SIMPLE authorizer response, setting isAuthorized = True and
  adding clientCertPem into the `context` map.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    logger.info(f"Authorizer event: {json.dumps(event)}")
    request_context = event.get("requestContext", {})

    # Log the full request context for debugging
    logger.info(f"RequestContext: {request_context}")

    # HTTP API Lambda authorizer v2.0 payload structure:
    # The client certificate can be in different locations depending on API Gateway version
    client_cert_pem = None

    # Try authentication.clientCert first (newer format)
    auth = request_context.get("authentication", {})
    if auth and "clientCert" in auth:
        client_cert_pem = auth.get("clientCert", {}).get("clientCertPem")
        logger.info(f"Found cert in authentication.clientCert: {bool(client_cert_pem)}")

    # Fallback: try identity.clientCert (from identity_source)
    if not client_cert_pem:
        identity = request_context.get("identity", {})
        if identity and "clientCert" in identity:
            client_cert_pem = identity.get("clientCert", {}).get("clientCertPem")
            logger.info(f"Found cert in identity.clientCert: {bool(client_cert_pem)}")

    # Also check if it's passed directly in the event (identity source variables)
    if not client_cert_pem:
        # Identity source variables might be at the root level
        client_cert_pem = event.get("clientCertPem") or event.get("clientCert", {}).get(
            "clientCertPem"
        )
        logger.info(f"Found cert in event root: {bool(client_cert_pem)}")

    if not client_cert_pem:
        logger.warning("ERROR: No client certificate found anywhere in event")
        logger.warning(f"Full event structure: {event}")
        # Return unauthorized instead of raising exception
        return {
            "isAuthorized": False,
        }

    logger.info(
        f"Client certificate PEM (first 50 chars): {client_cert_pem[:50] if client_cert_pem else 'None'}..."
    )

    # Extract additional certificate information if available
    client_cert = (
        request_context.get("authentication", {}).get("clientCert", {})
        or request_context.get("identity", {}).get("clientCert", {})
        or {}
    )
    subject_dn = client_cert.get("subjectDN", "")
    issuer_dn = client_cert.get("issuerDN", "")
    serial_number = client_cert.get("serialNumber", "")

    logger.info(f"Certificate subject: {subject_dn}")
    logger.info(f"Certificate issuer: {issuer_dn}")
    logger.info(f"Certificate serial: {serial_number}")

    # SIMPLE response type format for HTTP API Lambda authorizers:
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html
    response = {
        "isAuthorized": True,
        "context": {
            # This becomes available at $context.authorizer.clientCertPem
            "clientCertPem": client_cert_pem,
            "subjectDN": subject_dn,
            "issuerDN": issuer_dn,
            "serialNumber": serial_number,
        },
    }
    logger.info(
        f"Returning authorizer response: isAuthorized=True, context has clientCertPem: {bool(response['context'].get('clientCertPem'))}"
    )
    return response
