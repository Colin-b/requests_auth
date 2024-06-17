from responses import RequestsMock
from responses.matchers import urlencoded_params_matcher, header_matcher
import pytest
import requests

import requests_auth
import requests_auth._oauth2.authorization_code_pkce
from requests_auth.testing import BrowserMock, browser_mock, token_cache  # noqa: F401


def test_oauth2_pkce_flow_uses_provided_session(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    session = requests.Session()
    session.headers.update({"x-test": "Test value"})
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com",
        "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
        session=session,
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "code_verifier": "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx",
                    "grant_type": "authorization_code",
                    "redirect_uri": "http://localhost:5000/",
                    "client_id": "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
                    "scope": "openid",
                    "response_type": "code",
                    "code": "SplxlOBeZQQYbYS6WxSbIA",
                }
            ),
            header_matcher({"x-test": "Test value"}),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_oauth2_pkce_flow_uses_redirect_uri_domain(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com",
        "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
        redirect_uri_domain="localhost.mycompany.com",
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost.mycompany.com%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "code_verifier": "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx",
                    "grant_type": "authorization_code",
                    "redirect_uri": "http://localhost.mycompany.com:5000/",
                    "client_id": "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
                    "scope": "openid",
                    "response_type": "code",
                    "code": "SplxlOBeZQQYbYS6WxSbIA",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_oauth2_pkce_flow_get_code_is_sent_in_authorization_header_by_default(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "code_verifier": "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx",
                    "grant_type": "authorization_code",
                    "redirect_uri": "http://localhost:5000/",
                    "client_id": "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
                    "scope": "openid",
                    "response_type": "code",
                    "code": "SplxlOBeZQQYbYS6WxSbIA",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_okta_pkce_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "code_verifier": "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx",
                    "grant_type": "authorization_code",
                    "redirect_uri": "http://localhost:5000/",
                    "client_id": "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
                    "scope": "openid",
                    "response_type": "code",
                    "code": "SplxlOBeZQQYbYS6WxSbIA",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_okta_pkce_flow_token_custom_expiry(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com",
        "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_expires_in_sent_as_str(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "3600",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "code_verifier": "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx",
                    "grant_type": "authorization_code",
                    "redirect_uri": "http://localhost:5000/",
                    "client_id": "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
                    "scope": "openid",
                    "response_type": "code",
                    "code": "SplxlOBeZQQYbYS6WxSbIA",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_no_json(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        body="failure",
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "failure"
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: The request is missing a required parameter, includes an "
        "unsupported parameter value (other than grant type), repeats a parameter, "
        "includes multiple credentials, utilizes more than one mechanism for "
        "authenticating the client, or is otherwise malformed."
    )
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request", "error_description": "desc of the error"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "invalid_request: desc of the error"
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "http://test_url",
        },
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == f"invalid_request: desc of the error\nMore information can be found on http://test_url"
    )
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "http://test_url",
            "other": "other info",
        },
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == f"invalid_request: desc of the error\nMore information can be found on http://test_url\nAdditional information: {{'other': 'other info'}}"
    )
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_without_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"other": "other info"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "{'other': 'other info'}"
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_client_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_client"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_client: Client authentication failed (e.g., unknown client, no "
        "client authentication included, or unsupported authentication method).  The "
        "authorization server MAY return an HTTP 401 (Unauthorized) status code to "
        "indicate which HTTP authentication schemes are supported.  If the client "
        'attempted to authenticate via the "Authorization" request header field, the '
        "authorization server MUST respond with an HTTP 401 (Unauthorized) status "
        'code and include the "WWW-Authenticate" response header field matching the '
        "authentication scheme used by the client."
    )
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_grant_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_grant"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_grant: The provided authorization grant (e.g., authorization code, "
        "resource owner credentials) or refresh token is invalid, expired, revoked, "
        "does not match the redirection URI used in the authorization request, or was "
        "issued to another client."
    )
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_unauthorized_client_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "unauthorized_client"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unauthorized_client: The authenticated client is not authorized to use this "
        "authorization grant type."
    )
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_unsupported_grant_type_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "unsupported_grant_type"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unsupported_grant_type: The authorization grant type is not supported by the "
        "authorization server."
    )
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_scope_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_scope"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, malformed, or "
        "exceeds the scope granted by the resource owner."
    )
    tab.assert_success(
        "You are now authenticated on 5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b. You may close this tab."
    )


def test_with_invalid_token_request_invalid_request_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=invalid_request",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )


def test_with_invalid_token_request_invalid_request_error_and_error_description(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "invalid_request: desc"
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_request: desc"
    )


def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc&error_uri=http://test_url",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: desc\nMore information can be found on http://test_url"
    )
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_request: desc\nMore information can be found on http://test_url"
    )


def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc&error_uri=http://test_url&other=test",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: desc\nMore information can be found on http://test_url\nAdditional information: {'other': ['test']}"
    )
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_request: desc\nMore information can be found on http://test_url\nAdditional information: {'other': ['test']}"
    )


def test_with_invalid_token_request_unauthorized_client_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=unauthorized_client",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unauthorized_client: The client is not authorized to request an authorization code or an access token using this method."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: unauthorized_client: The client is not authorized to request an authorization code or an access token using this method."
    )


def test_with_invalid_token_request_access_denied_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=access_denied",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "access_denied: The resource owner or authorization server denied the request."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: access_denied: The resource owner or authorization server denied the request."
    )


def test_with_invalid_token_request_unsupported_response_type_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=unsupported_response_type",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unsupported_response_type: The authorization server does not support obtaining an authorization code or an access token using this method."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: unsupported_response_type: The authorization server does not support obtaining an authorization code or an access token using this method."
    )


def test_with_invalid_token_request_invalid_scope_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=invalid_scope",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, or malformed."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_scope: The requested scope is invalid, unknown, or malformed."
    )


def test_with_invalid_token_request_server_error_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=server_error",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "server_error: The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )
    tab.assert_failure(
        "Unable to properly perform authentication: server_error: The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )


def test_with_invalid_token_request_temporarily_unavailable_error(
    token_cache, responses: RequestsMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=temporarily_unavailable",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "temporarily_unavailable: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )
    tab.assert_failure(
        "Unable to properly perform authentication: temporarily_unavailable: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaAuthorizationCodePKCE(
            "test_url",
            "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
            header_value="Bearer token",
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
