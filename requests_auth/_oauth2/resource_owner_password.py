from hashlib import sha512

import requests
import requests.auth

from requests_auth._authentication import SupportMultiAuth, _add_parameters
from requests_auth._oauth2.common import OAuth2, request_new_grant_with_post


class OAuth2ResourceOwnerPasswordCredentials(requests.auth.AuthBase, SupportMultiAuth):
    """
    Resource Owner Password Credentials Grant

    Describes an OAuth 2 resource owner password credentials (also called password) flow requests authentication.
    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.3
    """

    def __init__(self, token_url: str, username: str, password: str, **kwargs):
        """
        :param token_url: OAuth 2 token URL.
        :param username: Resource owner user name.
        :param password: Resource owner password.
        :param session_auth: Client authentication if the client type is confidential
        or the client was issued client credentials (or assigned other authentication requirements).
        Can be a tuple or any requests authentication class instance.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param scope: Scope parameter sent to token URL as body. Can also be a list of scopes. Not sent by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param session: requests.Session instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as body parameters in the token URL.
        """
        self.token_url = token_url
        if not self.token_url:
            raise Exception("Token URL is mandatory.")
        self.username = username
        if not self.username:
            raise Exception("User name is mandatory.")
        self.password = password
        if not self.password:
            raise Exception("Password is mandatory.")

        self.header_name = kwargs.pop("header_name", None) or "Authorization"
        self.header_value = kwargs.pop("header_value", None) or "Bearer {token}"
        if "{token}" not in self.header_value:
            raise Exception("header_value parameter must contains {token}.")

        self.token_field_name = kwargs.pop("token_field_name", None) or "access_token"
        self.early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

        # Time is expressed in seconds
        self.timeout = int(kwargs.pop("timeout", None) or 60)
        self.session = kwargs.pop("session", None) or requests.Session()
        session_auth = kwargs.pop("session_auth", None)
        if session_auth:
            self.session.auth = session_auth

        # As described in https://tools.ietf.org/html/rfc6749#section-4.3.2
        self.data = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
        }
        scope = kwargs.pop("scope", None)
        if scope:
            self.data["scope"] = " ".join(scope) if isinstance(scope, list) else scope
        self.data.update(kwargs)

        # As described in https://tools.ietf.org/html/rfc6749#section-6
        self.refresh_data = {"grant_type": "refresh_token"}
        if scope:
            self.refresh_data["scope"] = self.data["scope"]
        self.refresh_data.update(kwargs)

        all_parameters_in_url = _add_parameters(self.token_url, self.data)
        self.state = sha512(all_parameters_in_url.encode("unicode_escape")).hexdigest()

    def __call__(self, r):
        token = OAuth2.token_cache.get_token(
            key=self.state,
            early_expiry=self.early_expiry,
            on_missing_token=self.request_new_token,
            on_expired_token=self.refresh_token,
        )
        r.headers[self.header_name] = self.header_value.format(token=token)
        return r

    def request_new_token(self):
        # As described in https://tools.ietf.org/html/rfc6749#section-4.3.3
        token, expires_in, refresh_token = request_new_grant_with_post(
            self.token_url,
            self.data,
            self.token_field_name,
            self.timeout,
            self.session,
        )
        # Handle both Access and Bearer tokens
        return (
            (self.state, token, expires_in, refresh_token)
            if expires_in
            else (self.state, token)
        )

    def refresh_token(self, refresh_token: str):
        # As described in https://tools.ietf.org/html/rfc6749#section-6
        self.refresh_data["refresh_token"] = refresh_token
        token, expires_in, refresh_token = request_new_grant_with_post(
            self.token_url,
            self.refresh_data,
            self.token_field_name,
            self.timeout,
            self.session,
        )
        return self.state, token, expires_in, refresh_token


class OktaResourceOwnerPasswordCredentials(OAuth2ResourceOwnerPasswordCredentials):
    """
    Describes an Okta (OAuth 2) resource owner password credentials (also called password) flow requests authentication.
    """

    def __init__(
        self,
        instance: str,
        username: str,
        password: str,
        client_id: str,
        client_secret: str,
        **kwargs,
    ):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param username: Resource owner user name.
        :param password: Resource owner password.
        :param client_id: Okta Application Identifier (formatted as an Universal Unique Identifier)
        :param client_secret: Resource owner password.
        :param authorization_server: Okta authorization server
        default by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param scope: Scope parameter sent to token URL as body. Can also be a list of scopes.
        Request 'openid' by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param session: requests.Session instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as body parameters in the token URL.
        """
        if not instance:
            raise Exception("Instance is mandatory.")
        if not client_id:
            raise Exception("Client ID is mandatory.")
        if not client_secret:
            raise Exception("Client secret is mandatory.")
        authorization_server = kwargs.pop("authorization_server", None) or "default"
        scopes = kwargs.pop("scope", "openid")
        kwargs["scope"] = " ".join(scopes) if isinstance(scopes, list) else scopes
        OAuth2ResourceOwnerPasswordCredentials.__init__(
            self,
            f"https://{instance}/oauth2/{authorization_server}/v1/token",
            username=username,
            password=password,
            session_auth=(client_id, client_secret),
            **kwargs,
        )
