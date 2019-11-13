import re

from responses import RequestsMock
import requests

import requests_auth
from tests.oauth2_helper import (
    authenticated_service,
    token_cache,
    TIMEOUT,
    TEST_SERVICE_HOST,
)
from tests.auth_helper import get_header


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


def test_header_api_key_and_multiple_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    api_key_auth3 = requests_auth.HeaderApiKey(
        "my_provided_api_key3", header_name="X-Api-Key3"
    )
    header = get_header(responses, api_key_auth + (api_key_auth2 + api_key_auth3))
    assert header.get("X-Api-Key") == "my_provided_api_key"
    assert header.get("X-Api-Key2") == "my_provided_api_key2"
    assert header.get("X-Api-Key3") == "my_provided_api_key3"


def test_multiple_auth_and_header_api_key_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    api_key_auth3 = requests_auth.HeaderApiKey(
        "my_provided_api_key3", header_name="X-Api-Key3"
    )
    header = get_header(responses, (api_key_auth + api_key_auth2) + api_key_auth3)
    assert header.get("X-Api-Key") == "my_provided_api_key"
    assert header.get("X-Api-Key2") == "my_provided_api_key2"
    assert header.get("X-Api-Key3") == "my_provided_api_key3"


def test_multiple_auth_and_multiple_auth_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
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
    header = get_header(
        responses, (api_key_auth + api_key_auth2) + (api_key_auth3 + api_key_auth4)
    )
    assert header.get("X-Api-Key") == "my_provided_api_key"
    assert header.get("X-Api-Key2") == "my_provided_api_key2"
    assert header.get("X-Api-Key3") == "my_provided_api_key3"
    assert header.get("X-Api-Key4") == "my_provided_api_key4"


def test_basic_and_multiple_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    basic_auth = requests_auth.Basic("test_user", "test_pwd")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    api_key_auth3 = requests_auth.HeaderApiKey(
        "my_provided_api_key3", header_name="X-Api-Key3"
    )
    header = get_header(responses, basic_auth + (api_key_auth2 + api_key_auth3))
    assert header.get("Authorization") == "Basic dGVzdF91c2VyOnRlc3RfcHdk"
    assert header.get("X-Api-Key2") == "my_provided_api_key2"
    assert header.get("X-Api-Key3") == "my_provided_api_key3"


def test_query_api_key_and_multiple_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    api_key_auth = requests_auth.QueryApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.QueryApiKey(
        "my_provided_api_key2", query_parameter_name="api_key2"
    )
    api_key_auth3 = requests_auth.HeaderApiKey(
        "my_provided_api_key3", header_name="X-Api-Key3"
    )

    # Mock a dummy response
    responses.add(responses.GET, "http://authorized_only")
    # Send a request to this dummy URL with authentication
    response = requests.get(
        "http://authorized_only", auth=api_key_auth + (api_key_auth2 + api_key_auth3)
    )
    # Return headers received on this dummy URL
    assert (
        response.request.path_url
        == "/?api_key=my_provided_api_key&api_key2=my_provided_api_key2"
    )
    assert response.request.headers.get("X-Api-Key3") == "my_provided_api_key3"


def test_oauth2_resource_owner_password_and_api_key_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    resource_owner_password_auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
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
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    header = get_header(responses, resource_owner_password_auth + api_key_auth)
    assert header.get("Authorization") == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    assert header.get("X-Api-Key") == "my_provided_api_key"


def test_oauth2_resource_owner_password_and_multiple_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    resource_owner_password_auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
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
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    header = get_header(
        responses, resource_owner_password_auth + (api_key_auth + api_key_auth2)
    )
    assert header.get("Authorization") == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    assert header.get("X-Api-Key") == "my_provided_api_key"
    assert header.get("X-Api-Key2") == "my_provided_api_key2"


def test_oauth2_client_credential_and_api_key_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    resource_owner_password_auth = requests_auth.OAuth2ClientCredentials(
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
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    header = get_header(responses, resource_owner_password_auth + api_key_auth)
    assert header.get("Authorization") == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    assert header.get("X-Api-Key") == "my_provided_api_key"


def test_oauth2_client_credential_and_multiple_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    resource_owner_password_auth = requests_auth.OAuth2ClientCredentials(
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
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    header = get_header(
        responses, resource_owner_password_auth + (api_key_auth + api_key_auth2)
    )
    assert header.get("Authorization") == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    assert header.get("X-Api-Key") == "my_provided_api_key"
    assert header.get("X-Api-Key2") == "my_provided_api_key2"


def test_oauth2_authorization_code_and_api_key_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    authorization_code_auth = requests_auth.OAuth2AuthorizationCode(
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
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    header = get_header(responses, authorization_code_auth + api_key_auth)
    assert header.get("Authorization") == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    assert header.get("X-Api-Key") == "my_provided_api_key"


def test_oauth2_authorization_code_and_multiple_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    authorization_code_auth = requests_auth.OAuth2AuthorizationCode(
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
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    header = get_header(
        responses, authorization_code_auth + (api_key_auth + api_key_auth2)
    )
    assert header.get("Authorization") == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    assert header.get("X-Api-Key") == "my_provided_api_key"
    assert header.get("X-Api-Key2") == "my_provided_api_key2"


def test_oauth2_pkce_and_api_key_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    pkce_auth = requests_auth.OAuth2AuthorizationCodePKCE(
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
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    header = get_header(responses, pkce_auth + api_key_auth)
    assert header.get("Authorization") == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    assert header.get("X-Api-Key") == "my_provided_api_key"


def test_oauth2_pkce_and_multiple_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    pkce_auth = requests_auth.OAuth2AuthorizationCodePKCE(
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
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    header = get_header(responses, pkce_auth + (api_key_auth + api_key_auth2))
    assert header.get("Authorization") == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    assert header.get("X-Api-Key") == "my_provided_api_key"
    assert header.get("X-Api-Key2") == "my_provided_api_key2"


def test_oauth2_implicit_and_api_key_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    implicit_auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token", timeout=TIMEOUT
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    header = get_header(responses, implicit_auth + api_key_auth)
    assert re.match("^Bearer .*", header.get("Authorization"))
    assert header.get("X-Api-Key") == "my_provided_api_key"


def test_oauth2_implicit_and_multiple_authentication_can_be_combined(
    authenticated_service, token_cache, responses: RequestsMock
):
    implicit_auth = requests_auth.OAuth2Implicit(
        TEST_SERVICE_HOST + "/provide_token_as_access_token", timeout=TIMEOUT
    )
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    api_key_auth2 = requests_auth.HeaderApiKey(
        "my_provided_api_key2", header_name="X-Api-Key2"
    )
    header = get_header(responses, implicit_auth + (api_key_auth + api_key_auth2))
    assert re.match("^Bearer .*", header.get("Authorization"))
    assert header.get("X-Api-Key") == "my_provided_api_key"
    assert header.get("X-Api-Key2") == "my_provided_api_key2"
