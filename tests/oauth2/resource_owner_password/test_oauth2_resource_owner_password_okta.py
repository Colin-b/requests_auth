from responses import RequestsMock
from responses.matchers import header_matcher, urlencoded_params_matcher
import pytest
import requests

import requests_auth
from requests_auth.testing import token_cache  # noqa: F401


def test_oauth2_password_credentials_flow_uses_provided_session(
    token_cache, responses: RequestsMock
):
    session = requests.Session()
    session.headers.update({"x-test": "Test value"})
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        session=session,
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "test_user",
                    "password": "test_pwd",
                    "scope": "openid",
                }
            ),
            header_matcher({"x-test": "Test value"}),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_password_credentials_flow_token_is_sent_in_authorization_header_by_default(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "test_user",
                    "password": "test_pwd",
                    "scope": "openid",
                }
            ),
            header_matcher({"Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI="}),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_password_credentials_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="bdc39831ac59c0f65d36761e9b65656ae76223f2284c393a6e93fe4e09a2c0002e2638bbe02db2cc62928a2357be5e2e93b9fa4ac68729f4d28da180caae912a",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "test_user",
                    "password": "test_pwd",
                    "scope": "openid",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_password_credentials_flow_token_custom_expiry(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="bdc39831ac59c0f65d36761e9b65656ae76223f2284c393a6e93fe4e09a2c0002e2638bbe02db2cc62928a2357be5e2e93b9fa4ac68729f4d28da180caae912a",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_expires_in_sent_as_str(token_cache, responses: RequestsMock):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "3600",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "test_user",
                    "password": "test_pwd",
                    "scope": "openid",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_refresh_token(token_cache, responses: RequestsMock):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    # response for password grant
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "0",  # let the token expire immediately after the first request
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "test_user",
                    "password": "test_pwd",
                    "scope": "openid",
                }
            )
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    # response for refresh token grant
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "rVR7Syg5bjZtZYjbZIW",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                    "scope": "openid",
                }
            )
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer rVR7Syg5bjZtZYjbZIW"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_refresh_token_invalid(token_cache, responses: RequestsMock):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    # response for password grant
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "0",  # let the token expire immediately after the first request
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "test_user",
                    "password": "test_pwd",
                    "scope": "openid",
                }
            )
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    # response for refresh token grant
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request"},
        status=400,
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                    "scope": "openid",
                }
            )
        ],
    )

    # if refreshing the token fails, fallback to requesting a new token
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_refresh_token_access_token_not_expired(token_cache, responses: RequestsMock):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    # response for password grant
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 36000,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "test_user",
                    "password": "test_pwd",
                    "scope": "openid",
                }
            )
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    # expect Bearer token to remain the same
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_scope_is_sent_as_is_when_provided_as_str(token_cache, responses: RequestsMock):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        scope="my_scope+my_other_scope",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "test_user",
                    "password": "test_pwd",
                    "scope": "my_scope+my_other_scope",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_scope_is_sent_as_str_when_provided_as_list(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        scope=["my_scope", "my_other_scope"],
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "password",
                    "username": "test_user",
                    "password": "test_pwd",
                    "scope": "my_scope my_other_scope",
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_with_invalid_grant_request_no_json(token_cache, responses: RequestsMock):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        body="failure",
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "failure"


def test_with_invalid_grant_request_invalid_request_error(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: The request is missing a required parameter, includes an "
        "unsupported parameter value (other than grant type), repeats a parameter, "
        "includes multiple credentials, utilizes more than one mechanism for "
        "authenticating the client, or is otherwise malformed."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request", "error_description": "desc of the error"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "invalid_request: desc of the error"


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "http://test_url",
        },
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == f"invalid_request: desc of the error\nMore information can be found on http://test_url"
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "http://test_url",
            "other": "other info",
        },
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == f"invalid_request: desc of the error\nMore information can be found on http://test_url\nAdditional information: {{'other': 'other info'}}"
    )


def test_with_invalid_grant_request_without_error(token_cache, responses: RequestsMock):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"other": "other info"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "{'other': 'other info'}"


def test_with_invalid_grant_request_invalid_client_error(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_client"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_client: Client authentication failed (e.g., unknown client, no "
        "client authentication included, or unsupported authentication method).  The "
        "authorization server MAY return an HTTP 401 (Unauthorized) status code to "
        "indicate which HTTP authentication schemes are supported.  If the client "
        'attempted to authenticate via the "Authorization" request header field, the '
        "authorization server MUST respond with an HTTP 401 (Unauthorized) status "
        'code and include the "WWW-Authenticate" response header field matching the '
        "authentication scheme used by the client."
    )


def test_with_invalid_grant_request_invalid_grant_error(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_grant"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_grant: The provided authorization grant (e.g., authorization code, "
        "resource owner credentials) or refresh token is invalid, expired, revoked, "
        "does not match the redirection URI used in the authorization request, or was "
        "issued to another client."
    )


def test_with_invalid_grant_request_unauthorized_client_error(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "unauthorized_client"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unauthorized_client: The authenticated client is not authorized to use this "
        "authorization grant type."
    )


def test_with_invalid_grant_request_unsupported_grant_type_error(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "unsupported_grant_type"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unsupported_grant_type: The authorization grant type is not supported by the "
        "authorization server."
    )


def test_with_invalid_grant_request_invalid_scope_error(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_scope"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, malformed, or "
        "exceeds the scope granted by the resource owner."
    )


def test_without_expected_token(token_cache, responses: RequestsMock):
    auth = requests_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        token_field_name="not_provided",
    )
    responses.post(
        "https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    with pytest.raises(requests_auth.GrantNotProvided) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "not_provided not provided within {'access_token': '2YotnFZFEjr1zCsicMWpAA', 'token_type': 'example', 'expires_in': 3600, 'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA', 'example_parameter': 'example_value'}."
    )


def test_instance_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaResourceOwnerPasswordCredentials(
            "",
            username="test_user",
            password="test_pwd",
            client_id="test_user2",
            client_secret="test_pwd2",
        )
    assert str(exception_info.value) == "Instance is mandatory."


def test_user_name_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaResourceOwnerPasswordCredentials(
            "testserver.okta-emea.com",
            username="",
            password="test_pwd",
            client_id="test_user2",
            client_secret="test_pwd2",
        )
    assert str(exception_info.value) == "User name is mandatory."


def test_password_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaResourceOwnerPasswordCredentials(
            "testserver.okta-emea.com",
            username="test_user",
            password="",
            client_id="test_user2",
            client_secret="test_pwd2",
        )
    assert str(exception_info.value) == "Password is mandatory."


def test_client_id_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaResourceOwnerPasswordCredentials(
            "testserver.okta-emea.com",
            username="test_user",
            password="test_pwd",
            client_id="",
            client_secret="test_pwd2",
        )
    assert str(exception_info.value) == "Client ID is mandatory."


def test_client_secret_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaResourceOwnerPasswordCredentials(
            "testserver.okta-emea.com",
            username="test_user",
            password="test_pwd",
            client_id="test_user2",
            client_secret="",
        )
    assert str(exception_info.value) == "Client secret is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaResourceOwnerPasswordCredentials(
            "testserver.okta-emea.com",
            username="test_user",
            password="test_pwd",
            client_id="test_user2",
            client_secret="test_pwd2",
            header_value="Bearer token",
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
