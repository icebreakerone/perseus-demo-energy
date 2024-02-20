
import pytest
from fastapi.testclient import TestClient
from tests  import cert_response
from api.main import app

client = TestClient(app)




@pytest.fixture
def mock_introspect(mocker):
    return mocker.patch("api.main.auth.introspect")

def test_consumption_no_token():
    response = client.get("/api/v1/consumption")
    assert response.status_code == 401

def test_consumption_bad_token():
    response = client.get("/api/v1/consumption", headers={'Authorization': 'Bearer'})
    assert response.status_code == 401

def test_consumption(mock_introspect):
    """
    If introspection is successful, return data and 200
    """
    mock_introspect.return_value = ({}, {})
    response = client.get("/api/v1/consumption", headers={'Authorization': 'Bearer abc123', 'x-amzn-mtls-clientcert': cert_response(urlencoded=True)})
    assert response.status_code == 200