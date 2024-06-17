import pytest
from responses import RequestsMock

import requests_auth
from requests_auth.testing import token_cache_mock
from tests.auth_helper import get_header


@pytest.fixture
def token_mock() -> str:
    return "2YotnFZFEjr1zCsicMWpAA"


def test_oauth2_implicit_flow(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.OAuth2Implicit("http://provide_token")
    assert (
        get_header(responses, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


def test_okta_implicit_flow(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.OktaImplicit(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    assert (
        get_header(responses, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


def test_aad_implicit_flow(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.AzureActiveDirectoryImplicit(
        "45239d18-c68c-4c47-8bdd-ce71ea1d50cd", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    assert (
        get_header(responses, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


def test_okta_implicit_id_token_flow(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.OktaImplicitIdToken(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    assert (
        get_header(responses, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


def test_aad_implicit_id_token_flow(token_cache_mock, responses: RequestsMock):
    auth = requests_auth.AzureActiveDirectoryImplicitIdToken(
        "45239d18-c68c-4c47-8bdd-ce71ea1d50cd", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    assert (
        get_header(responses, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
