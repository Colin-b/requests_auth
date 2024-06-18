import time
import datetime

import requests
import pytest
from responses import RequestsMock
from responses.matchers import header_matcher

from requests_auth.testing import (
    BrowserMock,
    create_token,
    browser_mock,  # noqa: F401
    token_cache,  # noqa: F401
)
import requests_auth


def test_oauth2_implicit_flow_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2Implicit(None)
    assert str(exception_info.value) == "Authorization URL is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2Implicit("http://test_url", header_value="Bearer token")
    assert str(exception_info.value) == "header_value parameter must contains {token}."


def test_oauth2_implicit_flow_token_is_not_reused_if_a_url_parameter_is_changing(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth1 = requests_auth.OAuth2Implicit(
        "http://provide_token?response_type=custom_token&fake_param=1",
        token_field_name="custom_token",
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    first_token = create_token(expiry_in_1_hour)
    tab1 = browser_mock.add_response(
        opened_url="http://provide_token?response_type=custom_token&fake_param=1&state=5652a8138e3a99dab7b94532c73ed5b10f19405316035d1efdc8bf7e0713690485254c2eaff912040eac44031889ef0a5ed5730c8a111541120d64a898c31afe&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"custom_token={first_token}&state=5652a8138e3a99dab7b94532c73ed5b10f19405316035d1efdc8bf7e0713690485254c2eaff912040eac44031889ef0a5ed5730c8a111541120d64a898c31afe",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {first_token}"})],
    )

    requests.get("http://authorized_only", auth=auth1)

    # Ensure that the new token is different than previous one
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1, seconds=1)

    auth2 = requests_auth.OAuth2Implicit(
        "http://provide_token?response_type=custom_token&fake_param=2",
        token_field_name="custom_token",
    )
    second_token = create_token(expiry_in_1_hour)
    tab2 = browser_mock.add_response(
        opened_url="http://provide_token?response_type=custom_token&fake_param=2&state=5c3940ccf78ac6e7d6d8d06782d9fd95a533aa5425b616eaa38dc3ec9508fbd55152c58a0d8dd8a087e76b77902559285819a41cb78ce8713e5a3b974bf07ce9&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"custom_token={second_token}&state=5c3940ccf78ac6e7d6d8d06782d9fd95a533aa5425b616eaa38dc3ec9508fbd55152c58a0d8dd8a087e76b77902559285819a41cb78ce8713e5a3b974bf07ce9",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {second_token}"})],
    )

    requests.get("http://authorized_only", auth=auth2)

    tab1.assert_success()
    tab2.assert_success()


def test_oauth2_implicit_flow_token_is_reused_if_only_nonce_differs(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth1 = requests_auth.OAuth2Implicit(
        "http://provide_token?response_type=custom_token&nonce=1",
        token_field_name="custom_token",
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=custom_token&state=67b95d2c7555751d1d72c97c7cd9ad6630c8395e0eaa51ee86ac7e451211ded9cd98a7190848789fe93632d8960425710e93f1f5549c6c6bc328bf3865a85ff2&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%271%27%5D",
        reply_url="http://localhost:5000",
        data=f"custom_token={token}&state=67b95d2c7555751d1d72c97c7cd9ad6630c8395e0eaa51ee86ac7e451211ded9cd98a7190848789fe93632d8960425710e93f1f5549c6c6bc328bf3865a85ff2",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth1)

    auth2 = requests_auth.OAuth2Implicit(
        "http://provide_token?response_type=custom_token&nonce=2",
        token_field_name="custom_token",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth2)
    tab.assert_success()


def test_oauth2_implicit_flow_token_can_be_requested_on_a_custom_server_port(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    # TODO Should use a method to retrieve a free port instead
    available_port = 5002
    auth = requests_auth.OAuth2Implicit(
        "http://provide_token", redirect_uri_port=available_port
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5002%2F",
        reply_url="http://localhost:5002",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_uses_redirect_uri_domain(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit(
        "http://provide_token", redirect_uri_domain="localhost.mycompany.com"
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost.mycompany.com%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_uses_custom_success(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    requests_auth.OAuth2.display.success_html = (
        "<body><div>SUCCESS: {display_time}</div></body>"
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        displayed_html="<body><div>SUCCESS: {display_time}</div></body>",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_uses_custom_failure(
    token_cache, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    requests_auth.OAuth2.display.failure_html = "FAILURE: {display_time}\n{information}"
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request",
        displayed_html="FAILURE: {display_time}\n{information}",
    )

    with pytest.raises(requests_auth.InvalidGrantRequest):
        requests.get("http://authorized_only", auth=auth)

    tab.assert_failure(
        "invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )


def test_oauth2_implicit_flow_post_token_is_sent_in_authorization_header_by_default(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    expiry_in_29_seconds = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(seconds=29)
    token_cache._add_token(
        key="42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
        token=create_token(expiry_in_29_seconds),
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_token_custom_expiry(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit("http://provide_token", early_expiry=28)
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    expiry_in_29_seconds = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(seconds=29)
    token_cache._add_token(
        key="42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
        token=create_token(expiry_in_29_seconds),
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    token = create_token(expiry_in_29_seconds)
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_browser_opening_failure(token_cache, responses: RequestsMock, monkeypatch):
    import requests_auth._oauth2.authentication_responses_server

    auth = requests_auth.OAuth2Implicit("http://provide_token", timeout=0.1)

    class FakeBrowser:
        def open(self, url, new):
            return False

    monkeypatch.setattr(
        requests_auth._oauth2.authentication_responses_server.webbrowser,
        "get",
        lambda *args: FakeBrowser(),
    )

    responses.add(
        responses.GET,
        "http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
    )
    with pytest.raises(requests_auth.TimeoutOccurred) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "User authentication was not received within 0.1 seconds."
    )
    assert isinstance(exception_info.value, requests_auth.RequestsAuthException)
    assert isinstance(exception_info.value, requests.RequestException)


def test_browser_error(token_cache, responses: RequestsMock, monkeypatch):
    import requests_auth._oauth2.authentication_responses_server

    auth = requests_auth.OAuth2Implicit("http://provide_token", timeout=0.1)

    class FakeBrowser:
        def open(self, url, new):
            import webbrowser

            raise webbrowser.Error("Failure")

    monkeypatch.setattr(
        requests_auth._oauth2.authentication_responses_server.webbrowser,
        "get",
        lambda *args: FakeBrowser(),
    )

    responses.add(
        responses.GET,
        "http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
    )
    with pytest.raises(requests_auth.TimeoutOccurred) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "User authentication was not received within 0.1 seconds."
    )


def test_state_change(token_cache, responses: RequestsMock, browser_mock: BrowserMock):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}&state=123456",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_empty_token_is_invalid(token_cache, browser_mock: BrowserMock):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token=&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    with pytest.raises(requests_auth.InvalidToken) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert str(exception_info.value) == " is invalid."
    assert isinstance(exception_info.value, requests_auth.RequestsAuthException)
    assert isinstance(exception_info.value, requests.RequestException)
    tab.assert_success()


def test_token_without_expiry_is_invalid(token_cache, browser_mock: BrowserMock):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={create_token(None)}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    with pytest.raises(requests_auth.TokenExpiryNotProvided) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert str(exception_info.value) == "Expiry (exp) is not provided in None."
    assert isinstance(exception_info.value, requests_auth.RequestsAuthException)
    assert isinstance(exception_info.value, requests.RequestException)
    tab.assert_success()


def test_oauth2_implicit_flow_get_token_is_sent_in_authorization_header_by_default(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url=f"http://localhost:5000#access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_token_is_sent_in_requested_field(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit(
        "http://provide_token", header_name="Bearer", header_value="{token}"
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Bearer": token})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_can_send_a_custom_response_type_and_expects_token_to_be_received_with_this_name(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit(
        "http://provide_token",
        response_type="custom_token",
        token_field_name="custom_token",
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=custom_token&state=67b95d2c7555751d1d72c97c7cd9ad6630c8395e0eaa51ee86ac7e451211ded9cd98a7190848789fe93632d8960425710e93f1f5549c6c6bc328bf3865a85ff2&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"custom_token={token}&state=67b95d2c7555751d1d72c97c7cd9ad6630c8395e0eaa51ee86ac7e451211ded9cd98a7190848789fe93632d8960425710e93f1f5549c6c6bc328bf3865a85ff2",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_expects_token_in_id_token_if_response_type_is_id_token(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit(
        "http://provide_token", response_type="id_token"
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=id_token&state=87c4108ec0eb03599335333a40434a36674269690b6957fef684bfb6c5a849ce660ef7031aa874c44d67cd3eada8febdfce41efb1ed3bc53a0a7e716cbba025a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"id_token={token}&state=87c4108ec0eb03599335333a40434a36674269690b6957fef684bfb6c5a849ce660ef7031aa874c44d67cd3eada8febdfce41efb1ed3bc53a0a7e716cbba025a",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_expects_token_in_id_token_if_response_type_in_url_is_id_token(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit("http://provide_token?response_type=id_token")
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=id_token&state=87c4108ec0eb03599335333a40434a36674269690b6957fef684bfb6c5a849ce660ef7031aa874c44d67cd3eada8febdfce41efb1ed3bc53a0a7e716cbba025a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"id_token={token}&state=87c4108ec0eb03599335333a40434a36674269690b6957fef684bfb6c5a849ce660ef7031aa874c44d67cd3eada8febdfce41efb1ed3bc53a0a7e716cbba025a",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_expects_token_to_be_stored_in_access_token_by_default(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab.assert_success()


def test_oauth2_implicit_flow_token_is_reused_if_not_expired(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth1 = requests_auth.OAuth2Implicit("http://provide_token")
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=auth1)

    oauth2 = requests_auth.OAuth2Implicit("http://provide_token")
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {token}"})],
    )

    requests.get("http://authorized_only", auth=oauth2)
    tab.assert_success()


def test_oauth2_implicit_flow_post_failure_if_token_is_not_provided(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data="",
    )
    with pytest.raises(Exception) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert str(exception_info.value) == "access_token not provided within {}."
    tab.assert_failure("access_token not provided within {}.")


def test_oauth2_implicit_flow_get_failure_if_token_is_not_provided(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
    )
    with pytest.raises(Exception) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert str(exception_info.value) == "access_token not provided within {}."
    tab.assert_failure("access_token not provided within {}.")


def test_oauth2_implicit_flow_post_failure_if_state_is_not_provided(
    token_cache, browser_mock: BrowserMock
):
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={token}",
    )
    with pytest.raises(requests_auth.StateNotProvided) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == f"state not provided within {{'access_token': ['{token}']}}."
    )
    assert isinstance(exception_info.value, requests_auth.RequestsAuthException)
    assert isinstance(exception_info.value, requests.RequestException)
    tab.assert_failure(f"state not provided within {{'access_token': ['{token}']}}.")


def test_oauth2_implicit_flow_get_failure_if_state_is_not_provided(
    token_cache, browser_mock: BrowserMock
):
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url=f"http://localhost:5000#access_token={token}",
    )
    with pytest.raises(requests_auth.StateNotProvided) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == f"state not provided within {{'access_token': ['{token}'], 'requests_auth_redirect': ['1']}}."
    )
    tab.assert_failure(
        f"state not provided within {{'access_token': ['{token}'], 'requests_auth_redirect': ['1']}}."
    )


def test_with_invalid_token_request_invalid_request_error(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == "invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )
    tab.assert_failure(
        "invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )


def test_with_invalid_token_request_invalid_request_error_and_error_description(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert str(exception_info.value) == "invalid_request: desc"
    tab.assert_failure("invalid_request: desc")


def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc&error_uri=http://test_url",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == "invalid_request: desc\nMore information can be found on http://test_url"
    )
    tab.assert_failure(
        "invalid_request: desc<br>More information can be found on http://test_url"
    )


def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc&error_uri=http://test_url&other=test",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == "invalid_request: desc\nMore information can be found on http://test_url\nAdditional information: {'other': ['test']}"
    )
    tab.assert_failure(
        "invalid_request: desc<br>More information can be found on http://test_url<br>Additional information: {'other': ['test']}"
    )


def test_with_invalid_token_request_unauthorized_client_error(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=unauthorized_client",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == "unauthorized_client: The client is not authorized to request an authorization code or an access token using this method."
    )
    tab.assert_failure(
        "unauthorized_client: The client is not authorized to request an authorization code or an access token using this method."
    )


def test_with_invalid_token_request_access_denied_error(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=access_denied",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == "access_denied: The resource owner or authorization server denied the request."
    )
    tab.assert_failure(
        "access_denied: The resource owner or authorization server denied the request."
    )


def test_with_invalid_token_request_unsupported_response_type_error(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=unsupported_response_type",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == "unsupported_response_type: The authorization server does not support obtaining an authorization code or an access token using this method."
    )
    tab.assert_failure(
        "unsupported_response_type: The authorization server does not support obtaining an authorization code or an access token using this method."
    )


def test_with_invalid_token_request_invalid_scope_error(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_scope",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, or malformed."
    )
    tab.assert_failure(
        "invalid_scope: The requested scope is invalid, unknown, or malformed."
    )


def test_with_invalid_token_request_server_error_error(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=server_error",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == "server_error: The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )
    tab.assert_failure(
        "server_error: The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )


def test_with_invalid_token_request_temporarily_unavailable_error(
    token_cache, browser_mock: BrowserMock
):
    tab = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=temporarily_unavailable",
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token"),
        )
    assert (
        str(exception_info.value)
        == "temporarily_unavailable: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )
    tab.assert_failure(
        "temporarily_unavailable: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )


def test_oauth2_implicit_flow_failure_if_token_is_not_received_within_the_timeout_interval(
    token_cache, browser_mock: BrowserMock
):
    browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        # Simulate no redirect
        reply_url=None,
    )
    with pytest.raises(requests_auth.TimeoutOccurred) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit("http://provide_token", timeout=0.1),
        )
    assert (
        str(exception_info.value)
        == "User authentication was not received within 0.1 seconds."
    )


def test_oauth2_implicit_flow_token_is_requested_again_if_expired(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    # This token will expires in 100 milliseconds
    expiry_in_1_second = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(milliseconds=100)
    first_token = create_token(expiry_in_1_second)
    tab1 = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={first_token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {first_token}"})],
    )

    requests.get("http://authorized_only", auth=auth)

    # Wait to ensure that the token will be considered as expired
    time.sleep(0.2)

    # Token should now be expired, a new one should be requested
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    second_token = create_token(expiry_in_1_hour)
    tab2 = browser_mock.add_response(
        opened_url="http://provide_token?response_type=token&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"access_token={second_token}&state=42a85b271b7a652ca3cc4c398cfd3f01b9ad36bf9c945ba823b023e8f8b95c4638576a0e3dcc96838b838bec33ec6c0ee2609d62ed82480b3b8114ca494c0521",
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": f"Bearer {second_token}"})],
    )

    requests.get("http://authorized_only", auth=auth)
    tab1.assert_success()
    tab2.assert_success()
