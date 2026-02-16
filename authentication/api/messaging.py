"""
Message delivery module for sending revocation messages to applications.

A production implementation of this module must include robust error handling, retries, and support for asynchronous delivery.
See https://specification.trust.ib1.org/message-delivery-to-applications/1.0/
"""

import json
from typing import Optional

import requests
from rdflib import Graph, Namespace, URIRef

from . import models
from .keystores import get_mtls_cert_paths
from .logger import get_logger

logger = get_logger()

# RDF namespaces
IB1 = Namespace("https://registry.core.trust.ib1.org/ns/ib1#")
TRUST_FRAMEWORK_URL = "https://registry.core.trust.ib1.org/trust-framework"
REVOKE_MESSAGE_SUBJECT = "https://registry.trust.ib1.org/message/revoke"


def get_mtls_session() -> requests.Session:
    """Create an HTTP session configured with mTLS client certs if available."""
    session = requests.Session()
    cert_paths = get_mtls_cert_paths()
    if cert_paths:
        session.cert = cert_paths
    return session


def create_revocation_message(permission: models.Permission) -> dict:
    """
    Create a revocation message according to the IB1 message format specification.

    Args:
        permission: The revoked permission object

    Returns:
        Dictionary containing the message in the required format
    """
    message = {
        "ib1:message": TRUST_FRAMEWORK_URL,
        "subject": REVOKE_MESSAGE_SUBJECT,
        "body": {
            "account": permission.account,
            "client": permission.client,
            "license": permission.license,
            "revoked": (
                permission.revoked.isoformat() + "Z" if permission.revoked else None
            ),
            "refreshToken": permission.refreshToken,
            "evidenceId": permission.evidenceId,
        },
    }
    return message


def fetch_application_url(client_url: str) -> Optional[str]:
    """
    Fetch the Application RDF document from the Directory and extract the message delivery URL.

    Args:
        client_url: The Application URL from the Directory

    Returns:
        The message delivery URL (ib1:messageDelivery) or None if not found
    """
    try:
        logger.info(f"Fetching application RDF from Directory: {client_url}")
        session = get_mtls_session()
        response = session.get(
            client_url,
            headers={"Accept": "application/rdf+xml"},
            timeout=10,
        )
        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        logger.error(
            f"Failed to fetch application URL from Directory: {str(e)}", exc_info=True
        )
        return None
    except Exception as e:
        logger.error(f"Error parsing application RDF: {str(e)}", exc_info=True)
        return None
    graph = Graph()
    try:
        graph.parse(data=response.text, format="xml")
    except Exception as parse_error:
        # Try alternative formats if primary fails
        logger.warning(f"Failed to parse RDF: {str(parse_error)}")

    # Find the message delivery URL
    app_uri = URIRef(client_url)
    message_delivery = graph.value(app_uri, IB1.messageDelivery)

    if message_delivery:
        delivery_url = str(message_delivery)
        logger.info(f"Found message delivery URL: {delivery_url}")
        return delivery_url
    else:
        logger.warning(
            f"No ib1:messageDelivery found in application RDF for {client_url}"
        )
        return None


def deliver_message(message_json: str, delivery_url: str) -> bool:
    """
    Deliver a message to the application's delivery URL.

    Args:
        message_json: The message as JSON string
        delivery_url: The delivery URL from the Directory

    Returns:
        True if delivery succeeded, False otherwise
    """
    try:
        logger.info(f"Attempting to deliver message to {delivery_url}")

        headers = {"Content-Type": "application/json"}

        session = get_mtls_session()
        response = session.post(
            delivery_url,
            data=message_json,
            headers=headers,
            timeout=30,
        )

        if response.status_code in (200, 201, 202, 204):
            logger.info(
                f"Successfully delivered message to {delivery_url} "
                f"(status {response.status_code})"
            )
            return True
        else:
            logger.warning(
                f"Message delivery failed to {delivery_url}: "
                f"status {response.status_code}, response: {response.text[:200]}"
            )
            return False

    except requests.exceptions.Timeout:
        logger.warning(f"Timeout delivering message to {delivery_url}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Request error delivering message to {delivery_url}: {str(e)}",
            exc_info=True,
        )
        return False
    except Exception as e:
        logger.error(
            f"Unexpected error delivering message to {delivery_url}: {str(e)}",
            exc_info=True,
        )
        return False


def send_revocation_message(permission: models.Permission) -> bool:
    """
    Send a revocation message synchronously to the client application.

    Creates the message, fetches the delivery URL from the Directory,
    and delivers the message via HTTP POST.

    Args:
        permission: The revoked permission object

    Returns:
        True if the message was delivered successfully, False otherwise
    """
    message = create_revocation_message(permission)
    message_json = json.dumps(message)

    delivery_url = fetch_application_url(permission.client)
    if not delivery_url:
        logger.error(f"Could not find delivery URL for client {permission.client}")
        return False

    return deliver_message(message_json, delivery_url)
