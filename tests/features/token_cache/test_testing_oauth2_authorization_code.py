import pytest
import requests
from responses import RequestsMock
from responses.matchers import header_matcher

import requests_auth
from requests_auth.testing import token_cache_mock  # noqa: F401


@pytest.fixture
def token_mock() -> str:
    return "2YotnFZFEjr1zCsicMWpAA"


def test_oauth2_authorization_code_flow(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.OAuth2AuthorizationCode(
        "http://provide_code", "http://provide_access_token"
    )

    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_okta_authorization_code_flow(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )

    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_oauth2_authorization_code_pkce_flow(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.OAuth2AuthorizationCodePKCE(
        "http://provide_code", "http://provide_access_token"
    )

    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_okta_authorization_code_pkce_flow(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )

    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA"})],
    )

    requests.get("http://authorized_only", auth=auth)
