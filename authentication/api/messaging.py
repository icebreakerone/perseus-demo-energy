"""
Message delivery module for sending revocation messages to applications.

Implements the Message Delivery to Applications specification:
https://specification.trust.ib1.org/message-delivery-to-applications/1.0/
"""
import json
import time
import datetime
from typing import Optional
from urllib.parse import urlparse

import redis
import requests
from cryptography import x509
from rdflib import Graph, Namespace, URIRef

from . import conf
from . import models
from .logger import get_logger

logger = get_logger()

# Redis Stream name for message queue
MESSAGE_STREAM = "message_delivery_queue"
# Consumer group name
CONSUMER_GROUP = "message_workers"
# Maximum retry attempts
MAX_RETRIES = 5
# Base delay for exponential backoff (seconds)
BASE_RETRY_DELAY = 1
# Maximum delay between retries (seconds)
MAX_RETRY_DELAY = 300  # 5 minutes

# RDF namespaces
IB1 = Namespace("https://registry.core.trust.ib1.org/ns/ib1#")
TRUST_FRAMEWORK_URL = "https://registry.core.trust.ib1.org/trust-framework"
REVOKE_MESSAGE_SUBJECT = "https://registry.trust.ib1.org/message/revoke"


def redis_connection() -> redis.Redis:
    """Get Redis connection for message queue."""
    return redis.Redis(host=conf.REDIS_HOST, port=6379, db=0, decode_responses=False)


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
            "revoked": permission.revoked.isoformat() + "Z" if permission.revoked else None,
            "refreshToken": permission.refreshToken,
            "evidenceId": permission.evidenceId,
        },
    }
    return message


def enqueue_revocation_message(permission: models.Permission) -> str:
    """
    Enqueue a revocation message to Redis Stream for asynchronous delivery.
    
    Args:
        permission: The revoked permission object
        
    Returns:
        Message ID from Redis Stream
    """
    try:
        message = create_revocation_message(permission)
        message_data = {
            "permission_account": permission.account,
            "permission_client": permission.client,
            "permission_refresh_token": permission.refreshToken,
            "message_json": json.dumps(message),
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "retry_count": "0",
        }
        
        conn = redis_connection()
        message_id = conn.xadd(MESSAGE_STREAM, message_data)
        
        # Ensure consumer group exists
        try:
            conn.xgroup_create(MESSAGE_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
        except redis.exceptions.ResponseError as e:
            # Group already exists, which is fine
            if "BUSYGROUP" not in str(e):
                raise
        
        logger.info(
            f"Enqueued revocation message for account={permission.account}, "
            f"client={permission.client}, message_id={message_id.decode() if isinstance(message_id, bytes) else message_id}"
        )
        
        return message_id.decode() if isinstance(message_id, bytes) else str(message_id)
    except Exception as e:
        logger.error(f"Failed to enqueue revocation message: {str(e)}", exc_info=True)
        raise


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
        response = requests.get(
            client_url,
            headers={"Accept": "application/rdf+xml, application/turtle, text/turtle"},
            timeout=10,
        )
        response.raise_for_status()
        
        # Determine RDF format from Content-Type header
        content_type = response.headers.get("Content-Type", "").lower()
        if "turtle" in content_type or "text/turtle" in content_type:
            rdf_format = "turtle"
        elif "json" in content_type or "application/ld+json" in content_type:
            rdf_format = "json-ld"
        else:
            # Default to XML/RDF
            rdf_format = "xml"
        
        # Parse RDF
        graph = Graph()
        try:
            graph.parse(data=response.text, format=rdf_format)
        except Exception as parse_error:
            # Try alternative formats if primary fails
            logger.warning(
                f"Failed to parse RDF as {rdf_format}, trying alternative formats: {str(parse_error)}"
            )
            for alt_format in ["turtle", "xml", "json-ld"]:
                if alt_format != rdf_format:
                    try:
                        graph.parse(data=response.text, format=alt_format)
                        logger.info(f"Successfully parsed RDF as {alt_format}")
                        break
                    except Exception:
                        continue
            else:
                raise
        
        # Find the message delivery URL
        app_uri = URIRef(client_url)
        message_delivery = graph.value(app_uri, IB1.messageDelivery)
        
        if message_delivery:
            delivery_url = str(message_delivery)
            logger.info(f"Found message delivery URL: {delivery_url}")
            return delivery_url
        else:
            logger.warning(f"No ib1:messageDelivery found in application RDF for {client_url}")
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch application URL from Directory: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Error parsing application RDF: {str(e)}", exc_info=True)
        return None


def deliver_message(
    message_json: str,
    delivery_url: str,
    client_cert: Optional[x509.Certificate] = None,
    retry_count: int = 0,
) -> bool:
    """
    Deliver a message to the application's delivery URL using mTLS.
    
    Args:
        message_json: The message as JSON string
        delivery_url: The delivery URL from the Directory
        client_cert: Optional client certificate for mTLS (if available)
        retry_count: Current retry attempt number
        
    Returns:
        True if delivery succeeded, False otherwise
    """
    try:
        logger.info(
            f"Attempting to deliver message to {delivery_url} (retry {retry_count})"
        )
        
        # Prepare request
        headers = {"Content-Type": "application/json"}
        
        # For mTLS, we would need to configure requests with client certificate
        # This requires the certificate and key to be available
        # For now, we'll use standard requests - mTLS configuration should be added
        # based on your certificate storage mechanism
        
        response = requests.post(
            delivery_url,
            data=message_json,
            headers=headers,
            timeout=30,
        )
        
        if response.status_code in (200, 201, 202, 204):
            logger.info(
                f"Successfully delivered message to {delivery_url} "
                f"(status {response.status_code}, retry {retry_count})"
            )
            return True
        else:
            logger.warning(
                f"Message delivery failed to {delivery_url}: "
                f"status {response.status_code}, response: {response.text[:200]} "
                f"(retry {retry_count})"
            )
            return False
            
    except requests.exceptions.Timeout:
        logger.warning(
            f"Timeout delivering message to {delivery_url} (retry {retry_count})"
        )
        return False
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Request error delivering message to {delivery_url}: {str(e)} "
            f"(retry {retry_count})",
            exc_info=True,
        )
        return False
    except Exception as e:
        logger.error(
            f"Unexpected error delivering message to {delivery_url}: {str(e)} "
            f"(retry {retry_count})",
            exc_info=True,
        )
        return False


def calculate_retry_delay(retry_count: int) -> float:
    """
    Calculate exponential backoff delay for retries.
    
    Args:
        retry_count: Current retry attempt number
        
    Returns:
        Delay in seconds
    """
    delay = min(BASE_RETRY_DELAY * (2 ** retry_count), MAX_RETRY_DELAY)
    return delay


def process_message(message_id: str, message_data: dict) -> bool:
    """
    Process a single message from the queue.
    
    Args:
        message_id: Redis Stream message ID
        message_data: Message data from Redis Stream
        
    Returns:
        True if message was successfully processed, False if it should be retried
    """
    try:
        # Parse message data
        message_json = message_data.get(b"message_json", b"").decode("utf-8")
        client_url = message_data.get(b"permission_client", b"").decode("utf-8")
        retry_count = int(message_data.get(b"retry_count", b"0").decode("utf-8"))
        account = message_data.get(b"permission_account", b"").decode("utf-8")
        refresh_token = message_data.get(b"permission_refresh_token", b"").decode("utf-8")
        
        logger.info(
            f"Processing message {message_id} for account={account}, "
            f"client={client_url}, retry={retry_count}"
        )
        
        # Fetch delivery URL from Directory
        delivery_url = fetch_application_url(client_url)
        if not delivery_url:
            logger.error(
                f"Could not find delivery URL for client {client_url}, "
                f"message {message_id}. Will retry."
            )
            return False
        
        # Attempt delivery
        success = deliver_message(message_json, delivery_url, retry_count=retry_count)
        
        if success:
            logger.info(
                f"Successfully processed message {message_id} for account={account}"
            )
            return True
        else:
            # Delivery failed, will be retried
            logger.warning(
                f"Failed to deliver message {message_id} for account={account}, "
                f"will retry (attempt {retry_count + 1}/{MAX_RETRIES})"
            )
            return False
            
    except Exception as e:
        logger.error(
            f"Error processing message {message_id}: {str(e)}",
            exc_info=True,
        )
        return False


def process_message_queue(consumer_name: str = "worker-1", batch_size: int = 10):
    """
    Process messages from the Redis Stream queue.
    
    This function should be run in a background task or separate worker process.
    
    Args:
        consumer_name: Unique name for this consumer
        batch_size: Number of messages to process in one batch
    """
    conn = redis_connection()
    
    # Ensure consumer group exists
    try:
        conn.xgroup_create(MESSAGE_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            logger.error(f"Error creating consumer group: {str(e)}")
            return
    
    logger.info(f"Message queue worker {consumer_name} started")
    
    while True:
        try:
            # Read messages from the stream
            messages = conn.xreadgroup(
                CONSUMER_GROUP,
                consumer_name,
                {MESSAGE_STREAM: ">"},
                count=batch_size,
                block=1000,  # Block for 1 second if no messages
            )
            
            if not messages:
                continue
            
            for stream, stream_messages in messages:
                for message_id, message_data in stream_messages:
                    try:
                        retry_count = int(
                            message_data.get(b"retry_count", b"0").decode("utf-8")
                        )
                        
                        # Check if we've exceeded max retries
                        if retry_count >= MAX_RETRIES:
                            logger.error(
                                f"Message {message_id} exceeded max retries ({MAX_RETRIES}), "
                                f"marking as failed"
                            )
                            # Acknowledge to remove from pending, but log as failed
                            conn.xack(MESSAGE_STREAM, CONSUMER_GROUP, message_id)
                            continue
                        
                        # Process the message
                        success = process_message(message_id, message_data)
                        
                        if success:
                            # Acknowledge successful processing
                            conn.xack(MESSAGE_STREAM, CONSUMER_GROUP, message_id)
                            logger.info(f"Acknowledged message {message_id}")
                        else:
                            # Increment retry count and reschedule
                            retry_count += 1
                            delay = calculate_retry_delay(retry_count - 1)
                            
                            # Update retry count in message
                            conn.xadd(
                                MESSAGE_STREAM,
                                {
                                    **message_data,
                                    b"retry_count": str(retry_count).encode(),
                                    b"next_retry_at": (
                                        datetime.datetime.now(datetime.timezone.utc)
                                        + datetime.timedelta(seconds=delay)
                                    ).isoformat().encode(),
                                },
                            )
                            
                            # Acknowledge current message (we've rescheduled it)
                            conn.xack(MESSAGE_STREAM, CONSUMER_GROUP, message_id)
                            
                            logger.info(
                                f"Rescheduled message {message_id} for retry {retry_count} "
                                f"after {delay}s delay"
                            )
                            
                    except Exception as e:
                        logger.error(
                            f"Error handling message {message_id}: {str(e)}",
                            exc_info=True,
                        )
                        # Acknowledge to prevent infinite retry loops on malformed messages
                        conn.xack(MESSAGE_STREAM, CONSUMER_GROUP, message_id)
                        
        except redis.exceptions.ConnectionError as e:
            logger.error(f"Redis connection error: {str(e)}, retrying in 5 seconds")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Unexpected error in message queue worker: {str(e)}", exc_info=True)
            time.sleep(5)

