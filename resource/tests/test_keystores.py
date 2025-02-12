import os


from unittest.mock import patch, mock_open
from botocore.exceptions import ClientError
from api.keystores import KeyNotFoundError
import api.auth
import pytest
from api.keystores import get_key
from cryptography.hazmat.primitives.asymmetric import ec

ROOT_DIR = os.path.dirname(os.path.realpath(__file__))


def valid_key():
    with open(f"{ROOT_DIR}/fixtures/test-suite-key.pem", "rb") as f:
        return f.read()


@patch("api.keystores.get_boto3_client")
@patch("builtins.open", new_callable=mock_open, read_data=valid_key())
def test_get_key_local_file(mock_open, mock_get_boto3_client):
    mock_ssm_client = mock_get_boto3_client.return_value
    mock_ssm_client.exceptions.ParameterNotFound = ClientError
    mock_ssm_client.exceptions.ClientError = ClientError
    mock_ssm_client.get_parameter.side_effect = ClientError(
        {
            "Error": {
                "Code": "ParameterNotFound",
                "Message": "Parameter not found",
            }
        },
        "get_parameter",
    )
    key = get_key("test_key_path")
    mock_open.assert_called_once_with(api.keystores.conf.SIGNING_KEY, "rb")
    assert isinstance(key, ec.EllipticCurvePrivateKey)


@patch("api.keystores.get_boto3_client")
def test_get_key_ssm(mock_get_boto3_client):
    mock_ssm_client = mock_get_boto3_client.return_value
    mock_ssm_client.exceptions.ParameterNotFound = ClientError
    mock_ssm_client.exceptions.ClientError = ClientError
    with open(
        f"{ROOT_DIR}/fixtures/test-suite-key.pem", "r"
    ) as f:  # SSM keys are stored as secure strings, not bytes
        return f.read()
    mock_ssm_client.get_parameter.return_value = {"Parameter": {"Value": valid_key()}}
    key = get_key("test_key_path")
    mock_ssm_client.get_parameter.assert_called_once_with(
        Name="test_key_path", WithDecryption=True
    )
    assert isinstance(key, ec.EllipticCurvePrivateKey)


@patch("api.keystores.get_boto3_client")
@patch("builtins.open", new_callable=mock_open)
def test_get_key_not_found(mock_open, mock_get_boto3_client):
    mock_ssm_client = mock_get_boto3_client.return_value
    mock_ssm_client.exceptions.ParameterNotFound = ClientError
    mock_ssm_client.exceptions.ClientError = ClientError
    mock_ssm_client.get_parameter.side_effect = ClientError(
        {
            "Error": {
                "Code": "ParameterNotFound",
                "Message": "Parameter not found",
            }
        },
        "get_parameter",
    )
    mock_open.side_effect = KeyNotFoundError
    with pytest.raises(KeyNotFoundError):
        get_key("test_key_path")
