import requests
from responses import RequestsMock
from responses.matchers import header_matcher

import requests_auth


def test_basic_authentication_send_authorization_header(responses: RequestsMock):
    auth = requests_auth.Basic("test_user", "test_pwd")

    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Basic dGVzdF91c2VyOnRlc3RfcHdk"})],
    )

    requests.get("http://authorized_only", auth=auth)
