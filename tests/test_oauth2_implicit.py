import time
import re

import requests
import pytest
from responses import RequestsMock

from tests.oauth2_helper import (
    authenticated_service,
    token_cache,
    TEST_SERVICE_HOST,
    TIMEOUT,
)
from tests.auth_helper import get_header
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
    authenticated_service, token_cache, responses: RequestsMock
):
    auth1 = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST
        + "/provide_token_as_custom_token?response_type=custom_token&fake_param=1",
        timeout=TIMEOUT,
        token_field_name="custom_token",
    )

    token_on_auth1 = get_header(responses, auth1).get("Authorization")
    assert re.match("^Bearer .*", token_on_auth1)

    # Ensure that the new generated token will be different than previous one
    time.sleep(1)

    auth2 = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST
        + "/provide_token_as_custom_token?response_type=custom_token&fake_param=2",
        timeout=TIMEOUT,
        token_field_name="custom_token",
    )
    response = requests.get("http://authorized_only", auth=auth2)
    # Return headers received on this dummy URL
    token_on_auth2 = response.request.headers.get("Authorization")
    assert re.match("^Bearer .*", token_on_auth2)

    assert token_on_auth1 != token_on_auth2


def test_oauth2_implicit_flow_token_is_reused_if_only_nonce_differs(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth1 = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST
        + "/provide_token_as_custom_token?response_type=custom_token&nonce=1",
        timeout=TIMEOUT,
        token_field_name="custom_token",
    )
    token_on_auth1 = get_header(responses, auth1).get("Authorization")
    assert re.match("^Bearer .*", token_on_auth1)

    auth2 = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST
        + "/provide_token_as_custom_token?response_type=custom_token&nonce=2",
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
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_custom_token",
        timeout=TIMEOUT,
        response_type="custom_token",
        token_field_name="custom_token",
    )
    assert re.match("^Bearer .*", get_header(responses, auth).get("Authorization"))


def test_oauth2_implicit_flow_expects_token_in_id_token_if_response_type_is_id_token(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_id_token",
        timeout=TIMEOUT,
        response_type="id_token",
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
