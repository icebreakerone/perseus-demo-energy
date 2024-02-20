import pytest

import api.auth

from tests import cert_response, introspection_response


@pytest.fixture
def mock_parse_request(mocker):
    return mocker.patch("api.auth.parse_cert")


@pytest.fixture
def mock_check_token(mocker):
    return mocker.patch("api.auth.check_token")


def test_introspect(mock_check_token):
    # mock_parse_request.return_value = cert_response()
    mock_check_token.return_value = introspection_response()
    result = api.auth.introspect(cert_response(urlencoded=True), "any-token")
    assert "x-fapi-interaction-id" in result[1]


def test_introspect_certificate_fails(mock_check_token):
    mock_check_token.return_value = introspection_response()
    with pytest.raises(api.auth.AccessTokenNoCertificateError):
        api.auth.introspect(None, "any-token")


def test_introspect_active_fail(mock_check_token):
    mock_check_token.return_value = introspection_response(active=False)
    with pytest.raises(api.auth.AccessTokenInactiveError):
        api.auth.introspect(cert_response(urlencoded=True), "any-token")
