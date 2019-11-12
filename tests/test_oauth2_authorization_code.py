from responses import RequestsMock
import pytest

import requests_auth
from tests.oauth2_helper import (
    authenticated_service,
    token_cache,
    TIMEOUT,
    TEST_SERVICE_HOST,
)
from tests.auth_helper import get_header, get_request


def test_oauth2_authorization_code_flow_get_code_is_sent_in_authorization_header_by_default(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2AuthorizationCode(
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
        == "grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA"
    )


def test_nonce_is_sent_if_provided_in_authorization_url(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2AuthorizationCode(
        TEST_SERVICE_HOST + "/provide_code_as_anchor_code?nonce=123456",
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
        == "grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA"
    )


def test_response_type_can_be_provided_in_url(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2AuthorizationCode(
        TEST_SERVICE_HOST + "/provide_code_as_anchor_code?response_type=code",
        "http://provide_access_token",
        timeout=TIMEOUT,
        response_type="not_used",
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


def test_authorization_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2AuthorizationCode("", "http://test_url")
    assert str(exception_info.value) == "Authorization URL is mandatory."


def test_token_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2AuthorizationCode("http://test_url", "")
    assert str(exception_info.value) == "Token URL is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2AuthorizationCode(
            "http://test_url", "http://test_url", header_value="Bearer token"
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
