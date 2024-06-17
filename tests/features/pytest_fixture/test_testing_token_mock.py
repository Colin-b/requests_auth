import requests
from responses import RequestsMock
from responses.matchers import header_matcher

import requests_auth
from requests_auth.testing import token_cache_mock, token_mock  # noqa: F401


def test_token_mock(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    expected_token = requests_auth.OAuth2.token_cache.get_token("")

    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {expected_token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
