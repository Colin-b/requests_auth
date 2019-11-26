import pytest
from responses import RequestsMock

import requests_auth
from tests.auth_helper import get_header


def test_basic_and_api_key_authentication_can_be_combined_deprecated(
    responses: RequestsMock,
):
    basic_auth = requests_auth.Basic("test_user", "test_pwd")
    api_key_auth = requests_auth.HeaderApiKey("my_provided_api_key")
    with pytest.warns(DeprecationWarning):
        header = get_header(responses, requests_auth.Auths(basic_auth, api_key_auth))
    assert header.get("Authorization") == "Basic dGVzdF91c2VyOnRlc3RfcHdk"
    assert header.get("X-Api-Key") == "my_provided_api_key"
