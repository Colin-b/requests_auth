import pytest
import requests
from responses import RequestsMock
from responses.matchers import header_matcher, query_string_matcher


import requests_auth


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

    responses.get(
        "http://authorized_only",
        match=[header_matcher({"X-API-Key": "my_provided_api_key"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_query_api_key_is_sent_in_api_key_by_default(responses: RequestsMock):
    auth = requests_auth.QueryApiKey("my_provided_api_key")

    responses.get(
        "http://authorized_only",
        match=[query_string_matcher("api_key=my_provided_api_key")],
    )

    requests.get("http://authorized_only", auth=auth)


def test_header_api_key_can_be_sent_in_a_custom_field_name(responses: RequestsMock):
    auth = requests_auth.HeaderApiKey("my_provided_api_key", "X-API-HEADER-KEY")

    responses.get(
        "http://authorized_only",
        match=[header_matcher({"X-API-HEADER-KEY": "my_provided_api_key"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_query_api_key_can_be_sent_in_a_custom_field_name(responses: RequestsMock):
    auth = requests_auth.QueryApiKey("my_provided_api_key", "X-API-QUERY-KEY")

    responses.get(
        "http://authorized_only",
        match=[query_string_matcher("X-API-QUERY-KEY=my_provided_api_key")],
    )

    requests.get("http://authorized_only", auth=auth)
