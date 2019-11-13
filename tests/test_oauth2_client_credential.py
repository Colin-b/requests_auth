from responses import RequestsMock
import pytest

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


def test_token_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2ClientCredentials("", "test_user", "test_pwd")
    assert str(exception_info.value) == "Token URL is mandatory."


def test_user_name_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2ClientCredentials("http://test_url", "", "test_pwd")
    assert str(exception_info.value) == "User name is mandatory."


def test_password_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2ClientCredentials("http://test_url", "test_user", "")
    assert str(exception_info.value) == "Password is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2ClientCredentials(
            "http://test_url", "test_user", "test_pwd", header_value="Bearer token"
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
