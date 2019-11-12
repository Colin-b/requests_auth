from responses import RequestsMock

import requests_auth
from tests.auth_helper import get_header


def test_basic_authentication_send_authorization_header(responses: RequestsMock):
    auth = requests_auth.Basic("test_user", "test_pwd")
    assert (
        get_header(responses, auth).get("Authorization")
        == "Basic dGVzdF91c2VyOnRlc3RfcHdk"
    )
