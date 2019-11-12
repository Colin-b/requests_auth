import time
import multiprocessing
import logging
import urllib.request
import re

import requests
import pytest
from responses import RequestsMock


from tests import authenticated_test_service
import requests_auth


logger = logging.getLogger(__name__)


TEST_SERVICE_PORT = 5001  # TODO Should use a method to retrieve a free port instead
TEST_SERVICE_HOST = "http://localhost:{0}".format(TEST_SERVICE_PORT)
TIMEOUT = 10


def call(auth):
    # Send a request to a dummy URL with authentication
    requests.get("http://authorized_only", auth=auth)


def get_header(responses, auth):
    # Mock a dummy response
    responses.add(responses.GET, "http://authorized_only")
    # Send a request to this dummy URL with authentication
    response = requests.get("http://authorized_only", auth=auth)
    # Return headers received on this dummy URL
    return response.request.headers


def get_query_args(responses, auth):
    # Mock a dummy response
    responses.add(responses.GET, "http://authorized_only")
    # Send a request to this dummy URL with authentication
    response = requests.get("http://authorized_only", auth=auth)
    # Return headers received on this dummy URL
    return response.request.path_url


def can_connect_to_server(port: int):
    try:
        response = urllib.request.urlopen(
            "http://localhost:{0}/status".format(port), timeout=0.5
        )
        return response.code == 200
    except:
        return False


def _wait_for_server_to_be_started(port: int):
    for attempt in range(3):
        if can_connect_to_server(port):
            logger.info("Test server is started")
            break
        logger.info("Test server still not started...")
    else:
        raise Exception("Test server was not able to start.")


@pytest.fixture(scope="module")
def authenticated_service():
    test_service_process = multiprocessing.Process(
        target=authenticated_test_service.start_server, args=(TEST_SERVICE_PORT,)
    )
    test_service_process.start()
    _wait_for_server_to_be_started(TEST_SERVICE_PORT)
    yield test_service_process
    test_service_process.terminate()
    test_service_process.join(timeout=0.5)


@pytest.fixture
def token_cache():
    yield requests_auth.OAuth2.token_cache
    requests_auth.OAuth2.token_cache.clear()


def test_oauth2_implicit_flow_url_is_mandatory(authenticated_service, token_cache):
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2Implicit(None)
    assert str(exception_info.value) == "Authorization URL is mandatory."


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

    logger.info("Requesting a custom token with a different parameter in URL.")

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
        call(
            requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + "/do_not_provide_token", timeout=TIMEOUT
            )
        )
    assert str(exception_info.value) == "access_token not provided within {}."


def test_oauth2_implicit_flow_get_failure_if_token_is_not_provided(
    authenticated_service, token_cache
):
    with pytest.raises(Exception) as exception_info:
        call(
            requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + "/do_not_provide_token_as_anchor_token",
                timeout=TIMEOUT,
            )
        )
    assert str(exception_info.value) == "access_token not provided within {}."


def test_oauth2_implicit_flow_post_failure_if_state_is_not_provided(
    authenticated_service, token_cache
):
    with pytest.raises(Exception) as exception_info:
        call(
            requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST
                + "/provide_token_as_access_token_but_without_providing_state",
                timeout=TIMEOUT,
            )
        )
    assert re.match(
        "state not provided within {'access_token': \['.*'\]}.",
        str(exception_info.value),
    )


def test_oauth2_implicit_flow_get_failure_if_state_is_not_provided(
    authenticated_service, token_cache
):
    with pytest.raises(Exception) as exception_info:
        call(
            requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST
                + "/provide_token_as_anchor_access_token_but_without_providing_state",
                timeout=TIMEOUT,
            )
        )
    assert re.match(
        "state not provided within {'access_token': \['.*'\]}.",
        str(exception_info.value),
    )


def test_oauth2_implicit_flow_failure_if_token_is_not_received_within_the_timeout_interval(
    authenticated_service, token_cache
):
    with pytest.raises(Exception) as exception_info:
        call(
            requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + "/do_not_redirect", timeout=TIMEOUT
            )
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


def test_oauth2_password_credentials_flow_token_is_sent_in_authorization_header_by_default(
    authenticated_service, token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
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


def test_header_api_key_requires_an_api_key():
    with pytest.raises(Exception) as exception_info:
        requests_auth.HeaderApiKey(None)
    assert str(exception_info.value) == "API Key is mandatory."


def test_query_api_key_requires_an_api_key():
    with pytest.raises(Exception) as exception_info:
        requests_auth.QueryApiKey(None)
    assert str(exception_info.value) == "API Key is mandatory."


def test_header_api_key_is_sent_in_X_Api_Key_by_default(responses: RequestsMock):
    auth = requests_auth.HeaderApiKey("my_provided_api_key")
    assert get_header(responses, auth).get("X-Api-Key") == "my_provided_api_key"


def test_query_api_key_is_sent_in_api_key_by_default(responses: RequestsMock):
    auth = requests_auth.QueryApiKey("my_provided_api_key")
    assert get_query_args(responses, auth) == "/?api_key=my_provided_api_key"


def test_header_api_key_can_be_sent_in_a_custom_field_name(responses: RequestsMock):
    auth = requests_auth.HeaderApiKey("my_provided_api_key", "X-API-HEADER-KEY")
    assert get_header(responses, auth).get("X-Api-Header-Key") == "my_provided_api_key"


def test_query_api_key_can_be_sent_in_a_custom_field_name(responses: RequestsMock):
    auth = requests_auth.QueryApiKey("my_provided_api_key", "X-API-QUERY-KEY")
    assert get_query_args(responses, auth) == "/?X-API-QUERY-KEY=my_provided_api_key"


def test_basic_authentication_send_authorization_header(responses: RequestsMock):
    auth = requests_auth.Basic("test_user", "test_pwd")
    assert (
        get_header(responses, auth).get("Authorization")
        == "Basic dGVzdF91c2VyOnRlc3RfcHdk"
    )


def test_basic_and_api_key_authentication_can_be_combined(responses: RequestsMock):
    basic_auth = requests_auth.Basic("test_user", "test_pwd")
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    header = get_header(responses, basic_auth + api_key_auth)
    assert header.get("Authorization") == "Basic dGVzdF91c2VyOnRlc3RfcHdk"
    assert header.get("X-Api-Key") == "my_provided_api_key"


def test_basic_and_api_key_authentication_can_be_combined_deprecated(
    responses: RequestsMock,
):
    basic_auth = requests_auth.Basic("test_user", "test_pwd")
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    header = get_header(responses, requests_auth.Auths(basic_auth, api_key_auth))
    assert header.get("Authorization") == "Basic dGVzdF91c2VyOnRlc3RfcHdk"
    assert header.get("X-Api-Key") == "my_provided_api_key"
