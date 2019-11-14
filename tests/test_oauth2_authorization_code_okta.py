import requests_auth


def test_corresponding_oauth2_authorization_code_flow_instance():
    okta = requests_auth.OktaAuthorizationCode(
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
    )
    assert (
        okta.authorization_url
        == "https://testserver.okta-emea.com/oauth2/default/v1/authorize"
    )
    assert okta.token_url == "https://testserver.okta-emea.com/oauth2/default/v1/token"
    assert okta.token_data == {
        "client_id": "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
        "grant_type": "authorization_code",
        "redirect_uri": "http://localhost:5000/",
        "response_type": "code",
        "scope": "openid",
    }
