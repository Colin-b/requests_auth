import pytest
import requests
from responses import RequestsMock
from responses.matchers import header_matcher, urlencoded_params_matcher

import requests_auth
from requests_auth.testing import token_cache  # noqa: F401


def test_okta_client_credentials_flow_uses_provided_session(
    token_cache, responses: RequestsMock
):
    session = requests.Session()
    session.headers.update({"x-test": "Test value"})
    auth = requests_auth.OktaClientCredentials(
        "test_okta",
        client_id="test_user",
        client_secret="test_pwd",
        scope="dummy",
        session=session,
    )
    responses.post(
        "https://test_okta/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            header_matcher({"x-test": "Test value"}),
            urlencoded_params_matcher(
                {"grant_type": "client_credentials", "scope": "dummy"}
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_okta_client_credentials_flow_token_is_sent_in_authorization_header_by_default(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", scope="dummy"
    )
    responses.post(
        "https://test_okta/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {"grant_type": "client_credentials", "scope": "dummy"}
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_okta_client_credentials_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", scope="dummy"
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="7830dd38bb95d4ac6273bd1a208c3db2097ac2715c6d3fb646ef3ccd48877109dd4cba292cef535559747cf6c4f497bf0804994dfb1c31bb293d2774889c2cfb",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    responses.post(
        "https://test_okta/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {"grant_type": "client_credentials", "scope": "dummy"}
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_okta_client_credentials_flow_token_custom_expiry(
    token_cache, responses: RequestsMock
):
    auth = requests_auth.OktaClientCredentials(
        "test_okta",
        client_id="test_user",
        client_secret="test_pwd",
        scope="dummy",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="7830dd38bb95d4ac6273bd1a208c3db2097ac2715c6d3fb646ef3ccd48877109dd4cba292cef535559747cf6c4f497bf0804994dfb1c31bb293d2774889c2cfb",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=requests_auth._oauth2.tokens._to_expiry(expires_in=29),
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_expires_in_sent_as_str(token_cache, responses: RequestsMock):
    auth = requests_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", scope="dummy"
    )
    responses.post(
        "https://test_okta/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "3600",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match=[
            urlencoded_params_matcher(
                {"grant_type": "client_credentials", "scope": "dummy"}
            ),
        ],
    )
    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_scope_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaClientCredentials(
            "test_url", "test_user", "test_pwd", scope=""
        )
    assert str(exception_info.value) == "scope is mandatory."


def test_instance_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaClientCredentials("", "test_user", "test_pwd", scope="dummy")
    assert str(exception_info.value) == "Okta instance is mandatory."


def test_client_id_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaClientCredentials("test_url", "", "test_pwd", scope="dummy")
    assert str(exception_info.value) == "client_id is mandatory."


def test_client_secret_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaClientCredentials("test_url", "test_user", "", scope="dummy")
    assert str(exception_info.value) == "client_secret is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaClientCredentials(
            "test_url",
            "test_user",
            "test_pwd",
            scope="dummy",
            header_value="Bearer token",
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
