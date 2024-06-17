from responses import RequestsMock

import requests_auth
from requests_auth.testing import token_cache_mock, token_mock
from tests.auth_helper import get_header


def test_token_mock(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    expected_token = requests_auth.OAuth2.token_cache.get_token("")
    assert (
        get_header(responses, auth).get("Authorization") == f"Bearer {expected_token}"
    )
