from responses import RequestsMock
import pytest
import requests

import requests_auth
from tests.oauth2_helper import token_cache, browser_mock, BrowserMock
from tests.auth_helper import get_header, get_request


def test_oauth2_authorization_code_flow_get_code_is_sent_in_authorization_header_by_default(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2AuthorizationCode(
        "http://provide_code", "http://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=code&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de",
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
    tab.assert_success(
        "You are now authenticated on 163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de. You may close this tab."
    )


def test_empty_token_is_invalid(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2AuthorizationCode(
        "http://provide_code", "http://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=code&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de",
    )
    responses.add(
        responses.POST,
        "http://provide_access_token",
        json={
            "access_token": "",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    with pytest.raises(requests_auth.GrantNotProvided) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "access_token not provided within {'access_token': '', 'token_type': 'example', 'expires_in': 3600, 'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA', 'example_parameter': 'example_value'}."
    )
    tab.assert_success(
        "You are now authenticated on 163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de. You may close this tab."
    )


def test_nonce_is_sent_if_provided_in_authorization_url(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2AuthorizationCode(
        "http://provide_code?nonce=123456", "http://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=code&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de",
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
    tab.assert_success(
        "You are now authenticated on 163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de. You may close this tab."
    )


def test_response_type_can_be_provided_in_url(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2AuthorizationCode(
        "http://provide_code?response_type=my_code",
        "http://provide_access_token",
        response_type="not_used",
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=my_code&state=49b67a19e70f692c3fc09dd124e5782b41a86f4f4931e1cc938ccbb466eecf1b730edb9eb01e42005de77ce3dd5a016418f8e780f30c4477d71102fe03e39e62&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=49b67a19e70f692c3fc09dd124e5782b41a86f4f4931e1cc938ccbb466eecf1b730edb9eb01e42005de77ce3dd5a016418f8e780f30c4477d71102fe03e39e62",
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
        == "grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code=SplxlOBeZQQYbYS6WxSbIA"
    )
    tab.assert_success(
        "You are now authenticated on 49b67a19e70f692c3fc09dd124e5782b41a86f4f4931e1cc938ccbb466eecf1b730edb9eb01e42005de77ce3dd5a016418f8e780f30c4477d71102fe03e39e62. You may close this tab."
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
