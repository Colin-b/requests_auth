from responses import RequestsMock
import pytest

import requests_auth
from tests.auth_helper import get_header, get_request
from tests.oauth2_helper import token_cache, browser_mock, BrowserMock


def test_oauth2_pkce_flow_get_code_is_sent_in_authorization_header_by_default(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(requests_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = requests_auth.OAuth2AuthorizationCodePKCE(
        "http://provide_code", "http://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=code&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
        == "code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA"
    )
    tab.assert_success(
        "You are now authenticated on 163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de. You may close this tab."
    )


def test_nonce_is_sent_if_provided_in_authorization_url(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(requests_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = requests_auth.OAuth2AuthorizationCodePKCE(
        "http://provide_code?nonce=123456", "http://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=code&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
        == "code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA"
    )
    tab.assert_success(
        "You are now authenticated on 163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de. You may close this tab."
    )


def test_response_type_can_be_provided_in_url(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(requests_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = requests_auth.OAuth2AuthorizationCodePKCE(
        "http://provide_code?response_type=my_code",
        "http://provide_access_token",
        response_type="not_used",
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=%5B%27my_code%27%5D&state=b32e05720bd3722e0ac87bf72897a78b669a0810adf8da46b675793dcfe0f41a40f7d7fdda952bd73ea533a2462907d805adf8c1a162d51b99b2ddec0d411feb&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=b32e05720bd3722e0ac87bf72897a78b669a0810adf8da46b675793dcfe0f41a40f7d7fdda952bd73ea533a2462907d805adf8c1a162d51b99b2ddec0d411feb",
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
        == "code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=my_code&code=SplxlOBeZQQYbYS6WxSbIA"
    )
    tab.assert_success(
        "You are now authenticated on b32e05720bd3722e0ac87bf72897a78b669a0810adf8da46b675793dcfe0f41a40f7d7fdda952bd73ea533a2462907d805adf8c1a162d51b99b2ddec0d411feb. You may close this tab."
    )


def test_authorization_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2AuthorizationCodePKCE("", "http://test_url")
    assert str(exception_info.value) == "Authorization URL is mandatory."


def test_token_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2AuthorizationCodePKCE("http://test_url", "")
    assert str(exception_info.value) == "Token URL is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2AuthorizationCodePKCE(
            "http://test_url", "http://test_url", header_value="Bearer token"
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
