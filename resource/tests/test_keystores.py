from unittest.mock import patch, mock_open
from botocore.exceptions import ClientError
from api.keystores import KeyNotFoundError
import api.auth
import pytest


@patch("api.auth.ssm_client.get_parameter")
@patch("builtins.open", new_callable=mock_open, read_data=b"local_key_data")
def test_get_key_local_file(mock_open, mock_ssm_client):
    mock_ssm_client.side_effect = ClientError(
        {"Error": {"Code": "ParameterNotFound", "Message": "Parameter not found"}},
        "get_parameter",
    )
    expected_key = b"local_key_data"
    key = api.auth.get_key()
    mock_open.assert_called_once_with(api.auth.conf.SIGNING_KEY, "rb")
    assert key == expected_key
    assert isinstance(key, bytes)


@patch("api.auth.ssm_client.get_parameter")
def test_get_key_ssm(mock_ssm_client):
    mock_ssm_client.return_value = {"Parameter": {"Value": "ssm_key_data"}}
    expected_key = b"ssm_key_data"
    key = api.auth.get_key()
    mock_ssm_client.assert_called_once()
    assert key == expected_key
    assert isinstance(key, bytes)


@patch("api.auth.ssm_client.get_parameter")
@patch("builtins.open", new_callable=mock_open)
def test_get_key_not_found(mock_open, mock_ssm_client):
    mock_ssm_client.side_effect = ClientError(
        {"Error": {"Code": "ParameterNotFound", "Message": "Parameter not found"}},
        "get_parameter",
    )
    mock_open.side_effect = FileNotFoundError
    with pytest.raises(KeyNotFoundError):
        api.auth.get_key()
