import time
import re
import datetime

import requests
import pytest
import jwt
from responses import RequestsMock

from tests.oauth2_helper import (
    authenticated_service,
    token_cache,
    TEST_SERVICE_HOST,
    TIMEOUT,
    browser_mock,
    BrowserMock,
)
from tests.auth_helper import get_header
import requests_auth


def create_token(expiry):
    token = (
        jwt.encode({"exp": expiry}, "secret") if expiry else jwt.encode({}, "secret")
    )
    return token.decode("unicode_escape")


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
        timeout=TIMEOUT,
        token_field_name="custom_token",
    )
    expiry_in_1_hour = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    browser_mock.add_response(
        opened_url="http://provide_token?response_type=custom_token&fake_param=1&state=5652a8138e3a99dab7b94532c73ed5b10f19405316035d1efdc8bf7e0713690485254c2eaff912040eac44031889ef0a5ed5730c8a111541120d64a898c31afe&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"custom_token={create_token(expiry_in_1_hour)}&state=5652a8138e3a99dab7b94532c73ed5b10f19405316035d1efdc8bf7e0713690485254c2eaff912040eac44031889ef0a5ed5730c8a111541120d64a898c31afe",
    )

    token_on_auth1 = get_header(responses, auth1).get("Authorization")
    assert re.match("^Bearer .*", token_on_auth1)

    # Ensure that the new token is different than previous one
    expiry_in_1_hour = datetime.datetime.utcnow() + datetime.timedelta(
        hours=1, seconds=1
    )

    auth2 = requests_auth.OAuth2Implicit(
        "http://provide_token?response_type=custom_token&fake_param=2",
        timeout=TIMEOUT,
        token_field_name="custom_token",
    )
    browser_mock.add_response(
        opened_url="http://provide_token?response_type=custom_token&fake_param=2&state=5c3940ccf78ac6e7d6d8d06782d9fd95a533aa5425b616eaa38dc3ec9508fbd55152c58a0d8dd8a087e76b77902559285819a41cb78ce8713e5a3b974bf07ce9&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"custom_token={create_token(expiry_in_1_hour)}&state=5c3940ccf78ac6e7d6d8d06782d9fd95a533aa5425b616eaa38dc3ec9508fbd55152c58a0d8dd8a087e76b77902559285819a41cb78ce8713e5a3b974bf07ce9",
    )
    response = requests.get("http://authorized_only", auth=auth2)
    # Return headers received on this dummy URL
    token_on_auth2 = response.request.headers.get("Authorization")
    assert re.match("^Bearer .*", token_on_auth2)

    assert token_on_auth1 != token_on_auth2


def test_oauth2_implicit_flow_token_is_reused_if_only_nonce_differs(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth1 = requests_auth.OAuth2Implicit(
        "http://provide_token?response_type=custom_token&nonce=1",
        timeout=TIMEOUT,
        token_field_name="custom_token",
    )
    expiry_in_1_hour = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    browser_mock.add_response(
        opened_url="http://provide_token?response_type=custom_token&state=67b95d2c7555751d1d72c97c7cd9ad6630c8395e0eaa51ee86ac7e451211ded9cd98a7190848789fe93632d8960425710e93f1f5549c6c6bc328bf3865a85ff2&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%271%27%5D",
        reply_url="http://localhost:5000",
        data=f"custom_token={create_token(expiry_in_1_hour)}&state=67b95d2c7555751d1d72c97c7cd9ad6630c8395e0eaa51ee86ac7e451211ded9cd98a7190848789fe93632d8960425710e93f1f5549c6c6bc328bf3865a85ff2",
    )
    token_on_auth1 = get_header(responses, auth1).get("Authorization")
    assert re.match("^Bearer .*", token_on_auth1)

    auth2 = requests_auth.OAuth2Implicit(
        "http://provide_token?response_type=custom_token&nonce=2",
        timeout=TIMEOUT,
        token_field_name="custom_token",
    )
    response = requests.get("http://authorized_only", auth=auth2)
    # Return headers received on this dummy URL
    token_on_auth2 = response.request.headers.get("Authorization")
    assert re.match("^Bearer .*", token_on_auth2)

    assert token_on_auth1 == token_on_auth2


def test_oauth2_implicit_flow_token_can_be_requested_on_a_custom_server_port(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token",
        # TODO Should use a method to retrieve a free port instead
        redirect_uri_port=5002,
        timeout=TIMEOUT,
    )
    assert re.match("^Bearer .*", get_header(responses, auth).get("Authorization"))


def test_oauth2_implicit_flow_post_token_is_sent_in_authorization_header_by_default(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token", timeout=TIMEOUT
    )
    assert re.match("^Bearer .*", get_header(responses, auth).get("Authorization"))


def test_browser_opening_failure(
    authenticated_service, token_cache, responses: RequestsMock, monkeypatch
):
    import requests_auth.oauth2_authentication_responses_server

    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token", timeout=TIMEOUT
    )

    class FakeBrowser:
        def open(self, url, new):
            return False

    monkeypatch.setattr(
        requests_auth.oauth2_authentication_responses_server.webbrowser,
        "get",
        lambda *args: FakeBrowser(),
    )

    responses.add(
        responses.GET,
        "http://localhost:5001/provide_token_as_access_token?response_type=token&state=cff2b2458bda8efd4978b2896ca43c754655fb625dee68359621cd34bca9280ae83b5b854afd01e24094c1bdb15286dd765c7c172a00d7f983137ea6c8b97c04&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
    )
    with pytest.raises(requests_auth.TimeoutOccurred) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(
        exception_info.value
    ) == "User authentication was not received within {} seconds.".format(TIMEOUT)


def test_browser_error(
    authenticated_service, token_cache, responses: RequestsMock, monkeypatch
):
    import requests_auth.oauth2_authentication_responses_server

    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token", timeout=TIMEOUT
    )

    class FakeBrowser:
        def open(self, url, new):
            import webbrowser

            raise webbrowser.Error("Failure")

    monkeypatch.setattr(
        requests_auth.oauth2_authentication_responses_server.webbrowser,
        "get",
        lambda *args: FakeBrowser(),
    )

    responses.add(
        responses.GET,
        "http://localhost:5001/provide_token_as_access_token?response_type=token&state=cff2b2458bda8efd4978b2896ca43c754655fb625dee68359621cd34bca9280ae83b5b854afd01e24094c1bdb15286dd765c7c172a00d7f983137ea6c8b97c04&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
    )
    with pytest.raises(requests_auth.TimeoutOccurred) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(
        exception_info.value
    ) == "User authentication was not received within {} seconds.".format(TIMEOUT)


def test_state_change(authenticated_service, token_cache, responses: RequestsMock):
    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token_with_another_state",
        timeout=TIMEOUT,
    )
    assert re.match("^Bearer .*", get_header(responses, auth).get("Authorization"))


def test_empty_token_is_invalid(
    authenticated_service, token_cache, responses: RequestsMock
):
    with pytest.raises(requests_auth.InvalidToken) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + "/provide_empty_token_as_access_token",
                timeout=TIMEOUT,
            ),
        )
    assert str(exception_info.value) == " is invalid."


def test_token_without_expiry_is_invalid(
    authenticated_service, token_cache, responses: RequestsMock
):
    with pytest.raises(requests_auth.TokenExpiryNotProvided) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + "/provide_token_without_exp_as_access_token",
                timeout=TIMEOUT,
            ),
        )
    assert str(exception_info.value) == "Expiry (exp) is not provided in None."


def test_oauth2_implicit_flow_get_token_is_sent_in_authorization_header_by_default(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_anchor_access_token", timeout=TIMEOUT
    )
    assert re.match("^Bearer .*", get_header(responses, auth).get("Authorization"))


def test_oauth2_implicit_flow_token_is_sent_in_requested_field(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token",
        timeout=TIMEOUT,
        header_name="Bearer",
        header_value="{token}",
    )
    assert get_header(responses, auth).get("Bearer")


def test_oauth2_implicit_flow_can_send_a_custom_response_type_and_expects_token_to_be_received_with_this_name(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit(
        "http://provide_token",
        timeout=TIMEOUT,
        response_type="custom_token",
        token_field_name="custom_token",
    )
    expiry_in_1_hour = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    browser_mock.add_response(
        opened_url="http://provide_token?response_type=custom_token&state=67b95d2c7555751d1d72c97c7cd9ad6630c8395e0eaa51ee86ac7e451211ded9cd98a7190848789fe93632d8960425710e93f1f5549c6c6bc328bf3865a85ff2&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"custom_token={create_token(expiry_in_1_hour)}&state=67b95d2c7555751d1d72c97c7cd9ad6630c8395e0eaa51ee86ac7e451211ded9cd98a7190848789fe93632d8960425710e93f1f5549c6c6bc328bf3865a85ff2",
    )
    assert re.match("^Bearer .*", get_header(responses, auth).get("Authorization"))


def test_oauth2_implicit_flow_expects_token_in_id_token_if_response_type_is_id_token(
    token_cache, responses: RequestsMock, browser_mock: BrowserMock
):
    auth = requests_auth.OAuth2Implicit(
        "http://provide_token", timeout=TIMEOUT, response_type="id_token"
    )
    expiry_in_1_hour = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    browser_mock.add_response(
        opened_url="http://provide_token?response_type=id_token&state=87c4108ec0eb03599335333a40434a36674269690b6957fef684bfb6c5a849ce660ef7031aa874c44d67cd3eada8febdfce41efb1ed3bc53a0a7e716cbba025a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000",
        data=f"id_token={create_token(expiry_in_1_hour)}&state=87c4108ec0eb03599335333a40434a36674269690b6957fef684bfb6c5a849ce660ef7031aa874c44d67cd3eada8febdfce41efb1ed3bc53a0a7e716cbba025a",
    )
    assert re.match("^Bearer .*", get_header(responses, auth).get("Authorization"))


def test_oauth2_implicit_flow_expects_token_in_id_token_if_response_type_in_url_is_id_token(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_id_token?response_type=id_token",
        timeout=TIMEOUT,
    )
    assert re.match("^Bearer .*", get_header(responses, auth).get("Authorization"))


def test_oauth2_implicit_flow_expects_token_to_be_stored_in_access_token_by_default(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token", timeout=TIMEOUT
    )
    assert re.match("^Bearer .*", get_header(responses, auth).get("Authorization"))


def test_oauth2_implicit_flow_token_is_reused_if_not_expired(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth1 = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token", timeout=TIMEOUT
    )
    token1 = get_header(responses, auth1).get("Authorization")
    assert re.match("^Bearer .*", token1)

    oauth2 = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token", timeout=TIMEOUT
    )
    response = requests.get("http://authorized_only", auth=oauth2)
    # Return headers received on this dummy URL
    token2 = response.request.headers.get("Authorization")
    assert re.match("^Bearer .*", token2)

    # As the token should not be expired, this call should use the same token
    assert token1 == token2


def test_oauth2_implicit_flow_post_failure_if_token_is_not_provided(
    authenticated_service, token_cache
):
    with pytest.raises(Exception) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + "/do_not_provide_token", timeout=TIMEOUT
            ),
        )
    assert str(exception_info.value) == "access_token not provided within {}."


def test_oauth2_implicit_flow_get_failure_if_token_is_not_provided(
    authenticated_service, token_cache
):
    with pytest.raises(Exception) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + "/do_not_provide_token_as_anchor_token",
                timeout=TIMEOUT,
            ),
        )
    assert str(exception_info.value) == "access_token not provided within {}."


def test_oauth2_implicit_flow_post_failure_if_state_is_not_provided(
    authenticated_service, token_cache
):
    with pytest.raises(requests_auth.StateNotProvided) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST
                + "/provide_token_as_access_token_but_without_providing_state",
                timeout=TIMEOUT,
            ),
        )
    assert re.match(
        "state not provided within {'access_token': \['.*'\]}.",
        str(exception_info.value),
    )


def test_oauth2_implicit_flow_get_failure_if_state_is_not_provided(
    authenticated_service, token_cache
):
    with pytest.raises(requests_auth.StateNotProvided) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST
                + "/provide_token_as_anchor_access_token_but_without_providing_state",
                timeout=TIMEOUT,
            ),
        )
    assert re.match(
        "state not provided within {'access_token': \['.*'\]}.",
        str(exception_info.value),
    )


def test_oauth2_implicit_flow_failure_if_token_is_not_received_within_the_timeout_interval(
    authenticated_service, token_cache
):
    with pytest.raises(requests_auth.TimeoutOccurred) as exception_info:
        requests.get(
            "http://authorized_only",
            auth=requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + "/do_not_redirect", timeout=TIMEOUT
            ),
        )
    assert str(
        exception_info.value
    ) == "User authentication was not received within {timeout} seconds.".format(
        timeout=TIMEOUT
    )


def test_oauth2_implicit_flow_token_is_requested_again_if_expired(
    authenticated_service, token_cache, responses: RequestsMock
):
    # This token will expires in 1 seconds
    auth1 = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_a_token_expiring_in_1_second", timeout=TIMEOUT
    )
    token1 = get_header(responses, auth1).get("Authorization")
    assert re.match("^Bearer .*", token1)

    # Wait for 2 seconds to ensure that the token expiring in 1 seconds will be considered as expired
    time.sleep(2)

    # Token should now be expired, a new one should be requested
    auth2 = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_a_token_expiring_in_1_second", timeout=TIMEOUT
    )
    response = requests.get("http://authorized_only", auth=auth2)
    # Return headers received on this dummy URL
    token2 = response.request.headers.get("Authorization")
    assert re.match("^Bearer .*", token2)

    assert token1 != token2
