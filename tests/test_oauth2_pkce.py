from responses import RequestsMock

import requests_auth
from tests.auth_helper import get_header, get_request
from tests.oauth2_helper import (
    authenticated_service,
    token_cache,
    TIMEOUT,
    TEST_SERVICE_HOST,
)


def test_oauth2_pkce_flow_get_code_is_sent_in_authorization_header_by_default(
    authenticated_service, token_cache, responses: RequestsMock, monkeypatch
):
    monkeypatch.setattr(requests_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = requests_auth.OAuth2PKCE(
        TEST_SERVICE_HOST + "/provide_code_as_anchor_code",
        "http://provide_access_token",
        timeout=TIMEOUT,
    )

    responses.add(
        responses.POST,
        "http://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    assert (
        get_header(responses, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
    assert (
        get_request(responses, "http://provide_access_token/").body
        == "code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA"
    )
