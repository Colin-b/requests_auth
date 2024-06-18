import datetime

from responses import RequestsMock
import requests
from responses.matchers import header_matcher, query_string_matcher

import requests_auth
from requests_auth.testing import (
    BrowserMock,
    create_token,
    token_cache,
    browser_mock,
)  # noqa: F401
import requests_auth._oauth2.authorization_code_pkce


def test_basic_and_api_key_authentication_can_be_combined(responses: RequestsMock):
    basic_auth = requests_auth.Basic("test_user", "test_pwd")
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    auth = basic_auth & api_key_auth

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Basic dGVzdF91c2VyOnRlc3RfcHdk",
                    "X-API-Key": "my_provided_api_key",
                }
            )
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_header_api_key_and_multiple_authentication_can_be_combined(
    token_cache, responses: RequestsMock
):
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    api_key_auth3 = requests_auth.HeaderApiKey(
        "my_provided_api_key3", header_name="X-Api-Key3"
    )
    auth = api_key_auth & (api_key_auth2 & api_key_auth3)

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "X-API-Key": "my_provided_api_key",
                    "X-Api-Key2": "my_provided_api_key2",
                    "X-Api-Key3": "my_provided_api_key3",
                }
            )
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_multiple_auth_and_header_api_key_can_be_combined(
    token_cache, responses: RequestsMock
):
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    api_key_auth3 = requests_auth.HeaderApiKey(
        "my_provided_api_key3", header_name="X-Api-Key3"
    )
    auth = (api_key_auth & api_key_auth2) & api_key_auth3

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "X-API-Key": "my_provided_api_key",
                    "X-Api-Key2": "my_provided_api_key2",
                    "X-Api-Key3": "my_provided_api_key3",
                }
            )
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_multiple_auth_and_multiple_auth_can_be_combined(
    token_cache, responses: RequestsMock
):
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    api_key_auth3 = requests_auth.HeaderApiKey(
        "my_provided_api_key3", header_name="X-Api-Key3"
    )
    api_key_auth4 = requests_auth.HeaderApiKey(
        "my_provided_api_key4", header_name="X-Api-Key4"
    )
    auth = (api_key_auth & api_key_auth2) & (api_key_auth3 & api_key_auth4)

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "X-API-Key": "my_provided_api_key",
                    "X-Api-Key2": "my_provided_api_key2",
                    "X-Api-Key3": "my_provided_api_key3",
                    "X-Api-Key4": "my_provided_api_key4",
                }
            )
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_basic_and_multiple_authentication_can_be_combined(
    token_cache, responses: RequestsMock
):
    basic_auth = requests_auth.Basic("test_user", "test_pwd")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    api_key_auth3 = requests_auth.HeaderApiKey(
        "my_provided_api_key3", header_name="X-Api-Key3"
    )
    auth = basic_auth & (api_key_auth2 & api_key_auth3)

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Basic dGVzdF91c2VyOnRlc3RfcHdk",
                    "X-Api-Key2": "my_provided_api_key2",
                    "X-Api-Key3": "my_provided_api_key3",
                }
            )
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_query_api_key_and_multiple_authentication_can_be_combined(
    token_cache, responses: RequestsMock
):
    api_key_auth = requests_auth.QueryApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.QueryApiKey(
        "my_provided_api_key2", query_parameter_name="api_key2"
    )
    api_key_auth3 = requests_auth.HeaderApiKey(
        "my_provided_api_key3", header_name="X-Api-Key3"
    )
    auth = api_key_auth & (api_key_auth2 & api_key_auth3)

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "X-Api-Key3": "my_provided_api_key3",
                }
            ),
            query_string_matcher(
                "api_key=my_provided_api_key&api_key2=my_provided_api_key2"
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_resource_owner_password_and_api_key_authentication_can_be_combined(
    token_cache, responses: RequestsMock
):
    resource_owner_password_auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    auth = resource_owner_password_auth & api_key_auth
    responses.post(
        "http://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
                    "X-API-Key": "my_provided_api_key",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_resource_owner_password_and_multiple_authentication_can_be_combined(
    token_cache, responses: RequestsMock
):
    resource_owner_password_auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    auth = resource_owner_password_auth & (api_key_auth & api_key_auth2)

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
                    "X-API-Key": "my_provided_api_key",
                    "X-Api-Key2": "my_provided_api_key2",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_client_credential_and_api_key_authentication_can_be_combined(
    token_cache, responses: RequestsMock
):
    resource_owner_password_auth = requests_auth.OAuth2ClientCredentials(
        "http://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    auth = resource_owner_password_auth & api_key_auth

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
                    "X-API-Key": "my_provided_api_key",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_client_credential_and_multiple_authentication_can_be_combined(
    token_cache, responses: RequestsMock
):
    resource_owner_password_auth = requests_auth.OAuth2ClientCredentials(
        "http://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    auth = resource_owner_password_auth & (api_key_auth & api_key_auth2)

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
                    "X-API-Key": "my_provided_api_key",
                    "X-Api-Key2": "my_provided_api_key2",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_authorization_code_and_api_key_authentication_can_be_combined(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    authorization_code_auth = requests_auth.OAuth2AuthorizationCode(
        "http://provide_code", "http://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=code&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de",
    )
    responses.post(
        "http://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    auth = authorization_code_auth & api_key_auth

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
                    "X-API-Key": "my_provided_api_key",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success()


def test_oauth2_authorization_code_and_multiple_authentication_can_be_combined(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    authorization_code_auth = requests_auth.OAuth2AuthorizationCode(
        "http://provide_code", "http://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=code&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de",
    )
    responses.post(
        "http://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    auth = authorization_code_auth & (api_key_auth & api_key_auth2)

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
                    "X-API-Key": "my_provided_api_key",
                    "X-Api-Key2": "my_provided_api_key2",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success()


def test_oauth2_pkce_and_api_key_authentication_can_be_combined(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock, monkeypatch
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    pkce_auth = requests_auth.OAuth2AuthorizationCodePKCE(
        "http://provide_code", "http://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=code&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de",
    )
    responses.post(
        "http://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    auth = pkce_auth & api_key_auth

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
                    "X-API-Key": "my_provided_api_key",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success()


def test_oauth2_pkce_and_multiple_authentication_can_be_combined(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock, monkeypatch
):
    monkeypatch.setattr(
        requests_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
    pkce_auth = requests_auth.OAuth2AuthorizationCodePKCE(
        "http://provide_code", "http://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="http://provide_code?response_type=code&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=163f0455b3e9cad3ca04254e5a0169553100d3aa0756c7964d897da316a695ffed5b4f46ef305094fd0a88cfe4b55ff257652015e4aa8f87b97513dba440f8de",
    )
    responses.post(
        "http://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    auth = pkce_auth & (api_key_auth & api_key_auth2)

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
                    "X-API-Key": "my_provided_api_key",
                    "X-Api-Key2": "my_provided_api_key2",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success()


def test_oauth2_implicit_and_api_key_authentication_can_be_combined(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    implicit_auth = requests_auth.OAuth2Implicit("http://provide_token")
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    auth = implicit_auth & api_key_auth

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": f"Bearer {token}",
                    "X-API-Key": "my_provided_api_key",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success()


def test_oauth2_implicit_and_multiple_authentication_can_be_combined(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    implicit_auth = requests_auth.OAuth2Implicit("http://provide_token")
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    auth = implicit_auth & (api_key_auth & api_key_auth2)

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher(
                {
                    "Authorization": f"Bearer {token}",
                    "X-API-Key": "my_provided_api_key",
                    "X-Api-Key2": "my_provided_api_key2",
                }
            ),
        ],
    )

    requests.get("http://authorized_only", auth=auth)

    tab.assert_success()
