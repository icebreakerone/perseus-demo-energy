import datetime
import io
import json
from unittest.mock import patch, MagicMock

import pytest
import responses

from api.keystores import get_mtls_cert_paths, resolve_cert_path, _download_s3_to_tempfile
from api.messaging import (
    get_mtls_session,
    fetch_application_url,
    deliver_message,
    create_revocation_message,
    send_revocation_message,
)
from api.models import Permission


# --- Fixtures ---


@pytest.fixture
def permission():
    return Permission(
        oauthIssuer="https://api.example.com/issuer",
        client="https://directory.core.trust.ib1.org/application/123",
        license="https://registry.core.trust.ib1.org/scheme/perseus/license/test",
        account="test-account",
        lastGranted=datetime.datetime.now(datetime.timezone.utc),
        expires="2025-12-31T23:59Z",
        refreshToken="test-refresh-token",
        revoked=datetime.datetime.now(datetime.timezone.utc),
        dataAvailableFrom=datetime.datetime.now(datetime.timezone.utc),
        tokenIssuedAt=datetime.datetime.now(datetime.timezone.utc),
        tokenExpires=datetime.datetime.now(datetime.timezone.utc),
    )


@pytest.fixture(autouse=True)
def clear_lru_caches():
    """Clear lru_cache between tests so cached state doesn't leak."""
    _download_s3_to_tempfile.cache_clear()
    yield
    _download_s3_to_tempfile.cache_clear()


# --- get_mtls_cert_paths tests ---


@patch("api.keystores.conf")
def test_get_mtls_cert_paths_returns_none_when_unset(mock_conf):
    mock_conf.MTLS_CLIENT_BUNDLE = None
    mock_conf.MTLS_CLIENT_KEY = None
    assert get_mtls_cert_paths() is None


@patch("api.keystores.conf")
def test_get_mtls_cert_paths_returns_none_when_partial(mock_conf):
    mock_conf.MTLS_CLIENT_BUNDLE = "/certs/bundle.pem"
    mock_conf.MTLS_CLIENT_KEY = None
    assert get_mtls_cert_paths() is None


@patch("api.keystores.conf")
def test_get_mtls_cert_paths_with_local_paths(mock_conf):
    mock_conf.MTLS_CLIENT_BUNDLE = "/certs/bundle.pem"
    mock_conf.MTLS_CLIENT_KEY = "/certs/key.pem"
    result = get_mtls_cert_paths()
    assert result == ("/certs/bundle.pem", "/certs/key.pem")


@patch("api.keystores.get_boto3_client")
@patch("api.keystores.conf")
def test_get_mtls_cert_paths_with_s3_uris(mock_conf, mock_get_boto3_client):
    mock_conf.MTLS_CLIENT_BUNDLE = "s3://my-bucket/certs/bundle.pem"
    mock_conf.MTLS_CLIENT_KEY = "s3://my-bucket/certs/key.pem"

    mock_s3 = MagicMock()
    mock_get_boto3_client.return_value = mock_s3

    mock_s3.get_object.side_effect = [
        {"Body": io.BytesIO(b"bundle-content")},
        {"Body": io.BytesIO(b"key-content")},
    ]

    result = get_mtls_cert_paths()
    assert result is not None
    bundle_path, key_path = result

    with open(bundle_path, "rb") as f:
        assert f.read() == b"bundle-content"
    with open(key_path, "rb") as f:
        assert f.read() == b"key-content"

    assert mock_s3.get_object.call_count == 2
    mock_s3.get_object.assert_any_call(Bucket="my-bucket", Key="certs/bundle.pem")
    mock_s3.get_object.assert_any_call(Bucket="my-bucket", Key="certs/key.pem")


# --- resolve_cert_path tests ---


def test_resolve_cert_path_local():
    assert resolve_cert_path("/local/path.pem") == "/local/path.pem"


@patch("api.keystores.get_boto3_client")
def test_resolve_cert_path_s3(mock_get_boto3_client):
    mock_s3 = MagicMock()
    mock_get_boto3_client.return_value = mock_s3
    mock_s3.get_object.return_value = {"Body": io.BytesIO(b"cert-data")}

    result = resolve_cert_path("s3://bucket/path/cert.pem")
    assert result.endswith(".pem")

    with open(result, "rb") as f:
        assert f.read() == b"cert-data"


# --- get_mtls_session tests ---


@patch("api.messaging.get_mtls_cert_paths", return_value=None)
def test_get_mtls_session_without_certs(mock_certs):
    session = get_mtls_session()
    assert session.cert is None


@patch("api.messaging.get_mtls_cert_paths", return_value=("/certs/bundle.pem", "/certs/key.pem"))
def test_get_mtls_session_with_certs(mock_certs):
    session = get_mtls_session()
    assert session.cert == ("/certs/bundle.pem", "/certs/key.pem")


# --- fetch_application_url tests ---


APPLICATION_RDF = """<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:ib1="https://registry.core.trust.ib1.org/ns/ib1#">
  <rdf:Description rdf:about="https://directory.core.trust.ib1.org/application/123">
    <ib1:messageDelivery>https://app.example.com/messages</ib1:messageDelivery>
  </rdf:Description>
</rdf:RDF>
"""


@responses.activate
@patch("api.messaging.get_mtls_cert_paths", return_value=None)
def test_fetch_application_url_success(mock_certs):
    client_url = "https://directory.core.trust.ib1.org/application/123"
    responses.add(responses.GET, client_url, body=APPLICATION_RDF, status=200)

    result = fetch_application_url(client_url)
    assert result == "https://app.example.com/messages"


@responses.activate
@patch("api.messaging.get_mtls_cert_paths", return_value=None)
def test_fetch_application_url_http_error(mock_certs):
    client_url = "https://directory.core.trust.ib1.org/application/123"
    responses.add(responses.GET, client_url, status=500)

    result = fetch_application_url(client_url)
    assert result is None


@responses.activate
@patch("api.messaging.get_mtls_cert_paths", return_value=("/certs/b.pem", "/certs/k.pem"))
def test_fetch_application_url_uses_mtls_session(mock_certs):
    client_url = "https://directory.core.trust.ib1.org/application/123"
    responses.add(responses.GET, client_url, body=APPLICATION_RDF, status=200)

    result = fetch_application_url(client_url)
    assert result == "https://app.example.com/messages"


# --- deliver_message tests ---


@responses.activate
@patch("api.messaging.get_mtls_cert_paths", return_value=None)
def test_deliver_message_success(mock_certs):
    delivery_url = "https://app.example.com/messages"
    responses.add(responses.POST, delivery_url, status=200)

    result = deliver_message('{"test": true}', delivery_url)
    assert result is True


@responses.activate
@patch("api.messaging.get_mtls_cert_paths", return_value=None)
def test_deliver_message_failure(mock_certs):
    delivery_url = "https://app.example.com/messages"
    responses.add(responses.POST, delivery_url, status=500, body="Server Error")

    result = deliver_message('{"test": true}', delivery_url)
    assert result is False


@responses.activate
@patch("api.messaging.get_mtls_cert_paths", return_value=("/certs/b.pem", "/certs/k.pem"))
def test_deliver_message_uses_mtls_session(mock_certs):
    delivery_url = "https://app.example.com/messages"
    responses.add(responses.POST, delivery_url, status=202)

    result = deliver_message('{"test": true}', delivery_url)
    assert result is True


# --- send_revocation_message integration test ---


@responses.activate
@patch("api.messaging.get_mtls_cert_paths", return_value=None)
def test_send_revocation_message_success(mock_certs, permission):
    client_url = permission.client
    delivery_url = "https://app.example.com/messages"

    responses.add(responses.GET, client_url, body=APPLICATION_RDF, status=200)
    responses.add(responses.POST, delivery_url, status=200)

    result = send_revocation_message(permission)
    assert result is True


@responses.activate
@patch("api.messaging.get_mtls_cert_paths", return_value=None)
def test_send_revocation_message_no_delivery_url(mock_certs, permission):
    client_url = permission.client
    responses.add(responses.GET, client_url, status=404)

    result = send_revocation_message(permission)
    assert result is False
