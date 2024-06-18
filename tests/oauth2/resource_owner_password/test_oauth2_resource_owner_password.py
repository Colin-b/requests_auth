from responses import RequestsMock, Response
from responses.matchers import header_matcher, urlencoded_params_matcher
import pytest
import requests

import requests_auth
from requests_auth.testing import token_cache  # noqa: F401


def get_request(responses: RequestsMock, url: str) -> Response:
    for call in responses.calls:
        if call.request.url == url:
            # Pop out verified request (to be able to check multiple requests)
            responses.calls._calls.remove(call)
            return call.request


def test_oauth2_password_credentials_flow_uses_provided_session(
    token_cache, responses: RequestsMock
):
    session = requests.Session()
    session.headers.update({"x-test": "Test value"})
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token",
        username="test_user",
        password="test_pwd",
        session=session,
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_password_credentials_flow_does_not_authenticate_by_default(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
                }
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)

    token_request = get_request(responses, "http://provide_access_token/")
    assert "Authorization" not in token_request.headers


def test_oauth2_password_credentials_flow_authentication(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token",
        username="test_user",
        password="test_pwd",
        session_auth=("test_user2", "test_pwd2"),
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="db2be9203dd2718c7285319dde1270056808482fbf7fffa6a9362d092d1cf799b393dd15140ea13e4d76d1603e56390a6222ff7063736a1b686d317706b2c001",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token",
        username="test_user",
        password="test_pwd",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="db2be9203dd2718c7285319dde1270056808482fbf7fffa6a9362d092d1cf799b393dd15140ea13e4d76d1603e56390a6222ff7063736a1b686d317706b2c001",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_expires_in_sent_as_str(token_cache, responses: RequestsMock):
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    # response for password grant
    responses.post(
        "http://provide_access_token",
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
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    # response for password grant
    responses.post(
        "http://provide_access_token",
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
        "http://provide_access_token",
        json={"error": "invalid_request"},
        status=400,
        match=[
            urlencoded_params_matcher(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    # response for password grant
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token",
        username="test_user",
        password="test_pwd",
        scope="my_scope+my_other_scope",
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token",
        username="test_user",
        password="test_pwd",
        scope=["my_scope", "my_other_scope"],
    )
    responses.post(
        "http://provide_access_token",
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
            )
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_with_invalid_grant_request_no_json(token_cache, responses: RequestsMock):
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post("http://provide_access_token", body="failure", status=400)
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "failure"


def test_with_invalid_grant_request_invalid_request_error(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
        json={"error": "invalid_request", "error_description": "desc of the error"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "invalid_request: desc of the error"


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
        json={"other": "other info"},
        status=400,
    )
    with pytest.raises(requests_auth.InvalidGrantRequest) as exception_info:
        requests.get("http://authorized_only", auth=auth)
    assert str(exception_info.value) == "{'other': 'other info'}"


def test_with_invalid_grant_request_invalid_client_error(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token", username="test_user", password="test_pwd"
    )
    responses.post(
        "http://provide_access_token",
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
    auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
        "http://provide_access_token",
        username="test_user",
        password="test_pwd",
        token_field_name="not_provided",
    )
    responses.post(
        "http://provide_access_token",
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


def test_token_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2ResourceOwnerPasswordCredentials(
            "", "test_user", "test_pwd"
        )
    assert str(exception_info.value) == "Token URL is mandatory."


def test_user_name_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2ResourceOwnerPasswordCredentials(
            "http://test_url", "", "test_pwd"
        )
    assert str(exception_info.value) == "User name is mandatory."


def test_password_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2ResourceOwnerPasswordCredentials(
            "http://test_url", "test_user", ""
        )
    assert str(exception_info.value) == "Password is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OAuth2ResourceOwnerPasswordCredentials(
            "http://test_url", "test_user", "test_pwd", header_value="Bearer token"
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
