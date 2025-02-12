import os

import pytest

from tests import CLIENT_ID, CATALOG_ENTRY_URL, client_certificate  # noqa

ROOT_DIR = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture
def mock_parse_request(mocker):
    return mocker.patch("api.auth.parse_cert")


@pytest.fixture
def mock_check_token(mocker):
    return mocker.patch("api.auth.check_token")


@pytest.fixture
def mock_auth_server_verification_bundle(mocker):
    return mocker.patch(
        "api.auth.conf.AUTHENTICATON_SERVER_VERIFICATION_BUNDLE",
        f"{ROOT_DIR}/fixtures/test-suite-bundle.pem",
    )
