import logging
from functools import lru_cache

import boto3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from .exceptions import (
    KeyNotFoundError,
)

from . import conf

log = logging.getLogger(__name__)


@lru_cache(maxsize=None)
def get_boto3_client(service_name):
    return boto3.client(service_name)


def get_key(key_path: str) -> PrivateKeyTypes:
    """
    Return the key (stored in ssm as a secure string) as bytes.
    If the call to SSM get parameter fails, try to load the key from a local file defined as conf.SIGNING_KEY.

    Args:
        issuer_type (str): The type of issuer for which to retrieve the key. Defaults to "server".

    Raises:
        KeyNotFoundError: If the key is not found in both SSM and the local file.
        FileNotFoundError: If the local file defined in conf.SIGNING_KEY is not found.

    Returns:
        bytes: The key as bytes.


    """
    ssm_client = get_boto3_client("ssm")
    log.info(f"Getting {key_path}")
    try:
        param_value = ssm_client.get_parameter(Name=key_path, WithDecryption=True)[
            "Parameter"
        ]["Value"]
        key_pem = param_value.encode("utf-8")
    except (ssm_client.exceptions.ParameterNotFound, ssm_client.exceptions.ClientError):
        log.warning("signing key not found in SSM. Trying local file.")
        try:
            with open(conf.SIGNING_KEY, "rb") as key_file:
                key_pem = key_file.read()
        except FileNotFoundError:
            raise KeyNotFoundError("signing key not found in SSM or local file.")
    return serialization.load_pem_private_key(
        key_pem, password=None, backend=default_backend()
    )


def get_certificate(certificate_path: str) -> bytes:
    s3_client = get_boto3_client("s3")
    if certificate_path.startswith("s3://"):
        bucket, key = certificate_path.split("s3://")[1].split("/", 1)
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        certificate = obj["Body"].read()

    else:
        with open(certificate_path, "rb") as cert_file:
            certificate = cert_file.read()
    return certificate
