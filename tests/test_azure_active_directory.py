import requests_auth


def test_corresponding_oauth2_implicit_flow_instance(monkeypatch):
    monkeypatch.setattr(requests_auth.authentication.uuid, "uuid4", lambda *args: "27ddfeed4e-854b-4361-8e7a-eab371c9bc91")
    aad = requests_auth.AzureActiveDirectoryImplicit(
        '45239d18-c68c-4c47-8bdd-ce71ea1d50cd',
        '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
    )
    assert aad.grant_details.url == 'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize?' \
                                    'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd' \
                                    '&response_type=token' \
                                    '&state=900fe3bb417d9c729361548bc6d3f83ad881e0b030ac27b2b563ee44ddf563c368612e8ee5b483f43667e897c96551388f6dfbdef83558ba2d6367d3b40d0496' \
                                    '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F' \
                                    '&nonce=%5B%2727ddfeed4e-854b-4361-8e7a-eab371c9bc91%27%5D'
    assert str(aad) == "OAuth2Implicit(" \
                       "'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize', " \
                       "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', " \
                       "nonce='27ddfeed4e-854b-4361-8e7a-eab371c9bc91')"


def test_corresponding_oauth2_implicit_flow_instance_using_helper(monkeypatch):
    monkeypatch.setattr(requests_auth.authentication.uuid, "uuid4", lambda *args: "27ddfeed4e-854b-4361-8e7a-eab371c9bc91")
    aad = requests_auth.aad(
        requests_auth.OAuth2Flow.Implicit,
        '45239d18-c68c-4c47-8bdd-ce71ea1d50cd',
        '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
    )
    assert aad.grant_details.url == 'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize?' \
                                    'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd' \
                                    '&response_type=token' \
                                    '&state=900fe3bb417d9c729361548bc6d3f83ad881e0b030ac27b2b563ee44ddf563c368612e8ee5b483f43667e897c96551388f6dfbdef83558ba2d6367d3b40d0496' \
                                    '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F' \
                                    '&nonce=%5B%2727ddfeed4e-854b-4361-8e7a-eab371c9bc91%27%5D'
    assert str(aad) == "OAuth2Implicit(" \
                       "'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize', " \
                       "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', " \
                       "nonce='27ddfeed4e-854b-4361-8e7a-eab371c9bc91')"


def test_corresponding_oauth2_implicit_flow_id_token_instance(monkeypatch):
    monkeypatch.setattr(requests_auth.authentication.uuid, "uuid4", lambda *args: "27ddfeed4e-854b-4361-8e7a-eab371c9bc91")
    aad = requests_auth.AzureActiveDirectoryImplicitIdToken(
        '45239d18-c68c-4c47-8bdd-ce71ea1d50cd',
        '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
    )
    assert aad.grant_details.url == 'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize?' \
                                    'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd' \
                                    '&response_type=id_token' \
                                    '&state=c141cf16f45343f37ca8053b6d0c67bad30a777b00221132d5a4514dd23082994e553a9f9fb45224ab9c2da3380047b32948fc2bf233efddc2fbd5801fc1d2d9' \
                                    '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F' \
                                    '&nonce=%5B%2727ddfeed4e-854b-4361-8e7a-eab371c9bc91%27%5D'
    assert str(aad) == "OAuth2Implicit(" \
                       "'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize', " \
                       "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', " \
                       "response_type='id_token', " \
                       "token_field_name='id_token', " \
                       "nonce='27ddfeed4e-854b-4361-8e7a-eab371c9bc91')"
