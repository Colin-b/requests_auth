import pytest
from responses import RequestsMock


import requests_auth
from tests.auth_helper import get_header, get_query_args


def test_header_api_key_requires_an_api_key():
    with pytest.raises(Exception) as exception_info:
        requests_auth.HeaderApiKey(None)
    assert str(exception_info.value) == "API Key is mandatory."


def test_query_api_key_requires_an_api_key():
    with pytest.raises(Exception) as exception_info:
        requests_auth.QueryApiKey(None)
    assert str(exception_info.value) == "API Key is mandatory."


def test_header_api_key_is_sent_in_x_api_key_by_default(responses: RequestsMock):
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
