import pytest

import requests_auth


def test_corresponding_oauth2_authorization_code_flow_instance(monkeypatch):
    monkeypatch.setattr(requests_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    okta = requests_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    assert (
        okta.code_grant_details.url
        == "https://testserver.okta-emea.com/oauth2/default/v1/authorize?"
        "client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
        "&scope=openid"
        "&response_type=code"
        "&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b"
        "&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F"
        "&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc"
        "&code_challenge_method=S256"
    )

    assert (
        str(okta) == "OAuth2PKCE("
        "'https://testserver.okta-emea.com/oauth2/default/v1/authorize', "
        "'https://testserver.okta-emea.com/oauth2/default/v1/token', "
        "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', "
        "scope='openid')"
    )


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        requests_auth.OktaAuthorizationCodePKCE(
            "test_url",
            "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
            header_value="Bearer token",
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
