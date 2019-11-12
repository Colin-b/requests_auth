from responses import RequestsMock

import requests_auth
from tests.oauth2_helper import authenticated_service, token_cache, TIMEOUT
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
