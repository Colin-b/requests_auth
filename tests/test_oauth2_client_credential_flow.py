from responses import RequestsMock

import requests_auth
from tests.oauth2_helper import authenticated_service, token_cache, TIMEOUT
from tests.auth_helper import get_header


def test_oauth2_client_credentials_flow_token_is_sent_in_authorization_header_by_default(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2ClientCredentials(
        "http://provide_access_token",
        username="test_user",
        password="test_pwd",
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


def test_okta_client_credentials_flow_token_is_sent_in_authorization_header_by_default(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", timeout=TIMEOUT
    )
    responses.add(
        responses.POST,
        "https://test_okta/oauth2/default/v1/token",
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


def test_okta_client_credentials_flow_token_is_sent_in_authorization_header_by_default_using_helper(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.okta(
        requests_auth.OAuth2Flow.ClientCredentials,
        "test_okta",
        client_id="test_user",
        client_secret="test_pwd",
        timeout=TIMEOUT,
    )
    responses.add(
        responses.POST,
        "https://test_okta/oauth2/default/v1/token",
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
