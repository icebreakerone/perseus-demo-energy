import os
import tempfile
from functools import lru_cache
from typing import Optional

import boto3  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from .exceptions import (
    KeyNotFoundError,
)

from . import conf
from .logger import get_logger

logger = get_logger()


@lru_cache(maxsize=None)
def get_boto3_client(service_name):
    return boto3.client(service_name)


@lru_cache(maxsize=None)
def _download_s3_to_tempfile(s3_uri: str) -> str:
    """Download an S3 object to a temp file and return the path. Cached per URI."""
    parts = s3_uri.replace("s3://", "").split("/", 1)
    bucket, key = parts[0], parts[1]
    s3_client = get_boto3_client("s3")
    obj = s3_client.get_object(Bucket=bucket, Key=key)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(key)[1])
    tmp.write(obj["Body"].read())
    tmp.close()
    logger.info(f"Downloaded {s3_uri} to {tmp.name}")
    return tmp.name


def resolve_cert_path(path_or_uri: str) -> str:
    """If the path is an S3 URI, download it and return a local path. Otherwise return as-is."""
    if path_or_uri.startswith("s3://"):
        return _download_s3_to_tempfile(path_or_uri)
    return path_or_uri


def get_mtls_cert_paths() -> Optional[tuple[str, str]]:
    """
    Return (bundle_path, key_path) for mTLS client certs, or None if not configured.

    The tuple format matches requests.Session.cert = (cert, key).
    """
    if not conf.MTLS_CLIENT_BUNDLE or not conf.MTLS_CLIENT_KEY:
        return None
    bundle_path = resolve_cert_path(conf.MTLS_CLIENT_BUNDLE)
    key_path = resolve_cert_path(conf.MTLS_CLIENT_KEY)
    return (bundle_path, key_path)


def get_key(key_path: str) -> ec.EllipticCurvePrivateKey:
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
    logger.info(f"Getting {key_path}")
    try:
        param_value = ssm_client.get_parameter(Name=key_path, WithDecryption=True)[
            "Parameter"
        ]["Value"]
        key_pem = param_value.encode("utf-8")
    except (ssm_client.exceptions.ParameterNotFound, ssm_client.exceptions.ClientError):
        logger.warning("jwt signing key not found in SSM. Trying local file.")
        try:
            with open(key_path, "rb") as key_file:
                key_pem = key_file.read()
        except FileNotFoundError:
            raise KeyNotFoundError("jwt signing key not found in SSM or local file.")
    loaded_key = serialization.load_pem_private_key(
        key_pem, password=None, backend=default_backend()
    )
    if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
        raise TypeError("The private key is not an EllipticCurvePrivateKey")
    return loaded_key
