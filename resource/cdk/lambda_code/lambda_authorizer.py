import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    logger.info(f"Authorizer event: {json.dumps(event)}")

    # Extract certificate from API Gateway
    client_cert = (
        event.get("requestContext", {}).get("identity", {}).get("clientCert", {})
    )

    if not client_cert:
        logger.warning("No client certificate found in request")
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Client certificate required"}),
        }

    # Extract certificate PEM
    cert_pem = client_cert.get("clientCertPem", "")

    if not cert_pem:
        logger.warning("No certificate PEM found in client certificate")
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Invalid client certificate"}),
        }

    # Extract additional certificate information
    subject_dn = client_cert.get("subjectDN", "")
    issuer_dn = client_cert.get("issuerDN", "")
    serial_number = client_cert.get("serialNumber", "")

    logger.info(f"Certificate subject: {subject_dn}")
    logger.info(f"Certificate issuer: {issuer_dn}")
    logger.info(f"Certificate serial: {serial_number}")

    # Return authorization response with certificate context
    return {
        "principalId": subject_dn or "unknown",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": event["methodArn"],
                }
            ],
        },
        "context": {
            "clientCertPem": cert_pem,
            "subjectDN": subject_dn,
            "issuerDN": issuer_dn,
            "serialNumber": serial_number,
        },
    }
