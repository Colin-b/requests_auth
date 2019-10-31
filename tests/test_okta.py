import requests_auth


def test_corresponding_oauth2_implicit_flow_instance(monkeypatch):
    monkeypatch.setattr(requests_auth.authentication.uuid, "uuid4", lambda *args: "27ddfeed4e-854b-4361-8e7a-eab371c9bc91")
    okta = requests_auth.OktaImplicit(
        'testserver.okta-emea.com',
        '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
    )
    assert okta.grant_details.url == 'https://testserver.okta-emea.com/oauth2/v1/authorize?' \
                                     'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd' \
                                     '&scope=openid+profile+email' \
                                     '&response_type=token' \
                                     '&state=f52217fda42a2089f9624cd7a36bb15bff1fb713144cbefbf3ace96c06b0adff46f854c803a41aa09b4b8a6fedf188f4d0ce3f84a6164a6a5db1cd7c004f9d91' \
                                     '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F' \
                                     '&nonce=%5B%2727ddfeed4e-854b-4361-8e7a-eab371c9bc91%27%5D'
    assert str(okta) == "OAuth2Implicit(" \
                        "'https://testserver.okta-emea.com/oauth2/v1/authorize', " \
                        "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', " \
                        "nonce='27ddfeed4e-854b-4361-8e7a-eab371c9bc91', " \
                        "scope='openid profile email')"


def test_corresponding_oauth2_implicit_flow_instance_using_helper(monkeypatch):
    monkeypatch.setattr(requests_auth.authentication.uuid, "uuid4", lambda *args: "27ddfeed4e-854b-4361-8e7a-eab371c9bc91")
    okta = requests_auth.okta(
        requests_auth.OAuth2Flow.Implicit,
        'testserver.okta-emea.com',
        '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
    )
    assert okta.grant_details.url == 'https://testserver.okta-emea.com/oauth2/v1/authorize?' \
                                     'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd' \
                                     '&scope=openid+profile+email' \
                                     '&response_type=token' \
                                     '&state=f52217fda42a2089f9624cd7a36bb15bff1fb713144cbefbf3ace96c06b0adff46f854c803a41aa09b4b8a6fedf188f4d0ce3f84a6164a6a5db1cd7c004f9d91' \
                                     '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F' \
                                     '&nonce=%5B%2727ddfeed4e-854b-4361-8e7a-eab371c9bc91%27%5D'
    assert str(okta) == "OAuth2Implicit(" \
                        "'https://testserver.okta-emea.com/oauth2/v1/authorize', " \
                        "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', " \
                        "nonce='27ddfeed4e-854b-4361-8e7a-eab371c9bc91', " \
                        "scope='openid profile email')"


def test_corresponding_oauth2_implicit_flow_id_token_instance(monkeypatch):
    monkeypatch.setattr(requests_auth.authentication.uuid, "uuid4", lambda *args: "27ddfeed4e-854b-4361-8e7a-eab371c9bc91")
    okta = requests_auth.OktaImplicitIdToken(
        'testserver.okta-emea.com',
        '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
    )
    assert okta.grant_details.url == 'https://testserver.okta-emea.com/oauth2/v1/authorize?' \
                                     'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd' \
                                     '&response_type=id_token' \
                                     '&scope=openid+profile+email' \
                                     '&state=da5a9f82a677a9b3bf19ce2f063f336f1968b8960d4626b35f7d4c0aee68e48ae1a5d5994dc78c3deb043d0e431c5be0bb084c8ac39bd41d670780306329d5a8' \
                                     '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F' \
                                     '&nonce=%5B%2727ddfeed4e-854b-4361-8e7a-eab371c9bc91%27%5D'
    assert str(okta) == "OAuth2Implicit(" \
                        "'https://testserver.okta-emea.com/oauth2/v1/authorize', " \
                        "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', " \
                        "response_type='id_token', " \
                        "token_field_name='id_token', " \
                        "nonce='27ddfeed4e-854b-4361-8e7a-eab371c9bc91', " \
                        "scope='openid profile email')"


def test_corresponding_oauth2_authorization_code_flow_instance():
    okta = requests_auth.OktaAuthorizationCode(
        'testserver.okta-emea.com',
        '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
    )
    assert okta.code_grant_details.url == 'https://testserver.okta-emea.com/oauth2/default/v1/authorize?' \
                                          'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd' \
                                          '&scope=openid' \
                                          '&response_type=code' \
                                          '&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b' \
                                          '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F'

    assert str(okta) == "OAuth2AuthorizationCode(" \
                        "'https://testserver.okta-emea.com/oauth2/default/v1/authorize', " \
                        "'https://testserver.okta-emea.com/oauth2/default/v1/token', " \
                        "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', " \
                        "scope='openid')"
