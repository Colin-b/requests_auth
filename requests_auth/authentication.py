import sys
from hashlib import sha512
import uuid
import requests
import requests.auth

from requests_auth import oauth2_authentication_responses_server, oauth2_tokens
from requests_auth.errors import *

if sys.version_info.major > 2:
    # Python 3
    from urllib.parse import parse_qs, urlsplit, urlunsplit, urlencode
else:
    # Python 2
    from urllib import urlencode
    from urlparse import parse_qs, urlsplit, urlunsplit


def _add_parameters(initial_url, extra_parameters):
    """
    Add parameters to an URL and return the new URL.

    :param initial_url:
    :param extra_parameters: dictionary of parameters name and value.
    :return: the new URL containing parameters.
    """
    scheme, netloc, path, query_string, fragment = urlsplit(initial_url)
    query_params = parse_qs(query_string)

    for parameter_name in extra_parameters.keys():
        # TODO Handle parameters with a list as a value and submit PR to requests or Python
        query_params[parameter_name] = [extra_parameters[parameter_name]]

    new_query_string = urlencode(query_params, doseq=True)

    return urlunsplit((scheme, netloc, path, new_query_string, fragment))


def _pop_parameter(url, query_parameter_name):
    """
    Remove and return parameter of an URL.

    :param url: The URL containing (or not) the parameter.
    :param query_parameter_name: The query parameter to pop.
    :return: The new URL (without this parameter) and the parameter value (None if not found).
    """
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string)
    parameter_value = query_params.pop(query_parameter_name, None)
    new_query_string = urlencode(query_params, doseq=True)

    return urlunsplit((scheme, netloc, path, new_query_string, fragment)), parameter_value


def _contains_query_parameter(url, param_name):
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string)
    return param_name in query_params


def request_new_grant_with_post(url, data, grant_name, timeout, auth=None):
    response = requests.post(url, data=data, timeout=timeout, auth=auth)
    response.raise_for_status()

    content = response.json()
    token = content.get(grant_name)
    if not token:
        raise GrantNotProvided(grant_name, content)
    return token, content.get('expires_in')


class OAuth2:
    token_cache = oauth2_tokens.TokenMemoryCache()


class OAuth2ResourceOwnerPasswordCredentials(requests.auth.AuthBase):
    """
    Resource Owner Password Credentials Grant

    Describes an OAuth 2 resource owner password credentials (also called password) flow requests authentication.
    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.3
    """

    def __init__(self, token_url, username, password, **kwargs):
        """
        :param token_url: OAuth 2 token URL.
        :param username: Resource owner user name.
        :param password: Resource owner password.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param scope: Scope parameter sent to token URL as body. Can also be a list of scopes. Not sent by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param kwargs: all additional authorization parameters that should be put as body parameters in the token URL.
        """
        self.token_url = token_url
        if not self.token_url:
            raise Exception('Token URL is mandatory.')
        self.username = username
        if not self.username:
            raise Exception('User name is mandatory.')
        self.password = password
        if not self.password:
            raise Exception('Password is mandatory.')
        self.kwargs = kwargs

        extra_parameters = dict(kwargs)
        self.header_name = extra_parameters.pop('header_name', None) or 'Authorization'
        self.header_value = extra_parameters.pop('header_value', None) or 'Bearer {token}'
        if '{token}' not in self.header_value:
            raise Exception('header_value parameter must contains {token}.')

        self.token_field_name = extra_parameters.pop('token_field_name', None) or 'access_token'

        # Time is expressed in seconds
        self.timeout = int(extra_parameters.pop('timeout', None) or 60)

        # As described in https://tools.ietf.org/html/rfc6749#section-4.3.2
        self.data = {
            'grant_type': 'password',
            'username': self.username,
            'password': self.password,
        }
        scope = extra_parameters.pop('scope', None)
        if scope:
            self.data['scope'] = ' '.join(scope) if isinstance(scope, list) else scope
        self.data.update(extra_parameters)

        all_parameters_in_url = _add_parameters(self.token_url, self.data)
        self.state = sha512(all_parameters_in_url.encode('unicode_escape')).hexdigest()

    def __call__(self, r):
        token = OAuth2.token_cache.get_token(self.state, self.request_new_token)
        r.headers[self.header_name] = self.header_value.format(token=token)
        return r

    def request_new_token(self):
        # As described in https://tools.ietf.org/html/rfc6749#section-4.3.3
        token, expires_in = request_new_grant_with_post(
            self.token_url, self.data, self.token_field_name, self.timeout,
            auth=(self.username, self.password)
        )
        # Handle both Access and Bearer tokens
        return (self.state, token, expires_in) if expires_in else (self.state, token)

    def __str__(self):
        addition_args_str = ', '.join(["{0}='{1}'".format(key, value) for key, value in self.kwargs.items()])
        return "OAuth2ResourceOwnerPasswordCredentials('{0}', '{1}', '{2}', {3})".format(
            self.token_url, self.username, self.password, addition_args_str
        )


class OAuth2ClientCredentials(requests.auth.AuthBase):
    """
    Client Credentials Grant

    Describes an OAuth 2 client credentials (also called application) flow requests authentication.
    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.4
    """

    def __init__(self, token_url, username, password, **kwargs):
        """
        :param token_url: OAuth 2 token URL.
        :param username: Resource owner user name.
        :param password: Resource owner password.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param scope: Scope parameter sent to token URL as body. Can also be a list of scopes. Not sent by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter in the token URL.
        """
        self.token_url = token_url
        if not self.token_url:
            raise Exception('Token URL is mandatory.')
        self.username = username
        if not self.username:
            raise Exception('User name is mandatory.')
        self.password = password
        if not self.password:
            raise Exception('Password is mandatory.')
        self.kwargs = kwargs

        extra_parameters = dict(kwargs)
        self.header_name = extra_parameters.pop('header_name', None) or 'Authorization'
        self.header_value = extra_parameters.pop('header_value', None) or 'Bearer {token}'
        if '{token}' not in self.header_value:
            raise Exception('header_value parameter must contains {token}.')

        self.token_field_name = extra_parameters.pop('token_field_name', None) or 'access_token'

        # Time is expressed in seconds
        self.timeout = int(extra_parameters.pop('timeout', None) or 60)

        # As described in https://tools.ietf.org/html/rfc6749#section-4.4.2
        self.data = {
            'grant_type': 'client_credentials',
        }
        scope = extra_parameters.pop('scope', None)
        if scope:
            self.data['scope'] = ' '.join(scope) if isinstance(scope, list) else scope
        self.data.update(extra_parameters)

        all_parameters_in_url = _add_parameters(self.token_url, self.data)
        self.state = sha512(all_parameters_in_url.encode('unicode_escape')).hexdigest()

    def __call__(self, r):
        token = OAuth2.token_cache.get_token(self.state, self.request_new_token)
        r.headers[self.header_name] = self.header_value.format(token=token)
        return r

    def request_new_token(self):
        # As described in https://tools.ietf.org/html/rfc6749#section-4.4.3
        token, expires_in = request_new_grant_with_post(
            self.token_url, self.data, self.token_field_name, self.timeout,
            auth=(self.username, self.password)
        )
        # Handle both Access and Bearer tokens
        return (self.state, token, expires_in) if expires_in else (self.state, token)

    def __str__(self):
        addition_args_str = ', '.join(["{0}='{1}'".format(key, value) for key, value in self.kwargs.items()])
        return "OAuth2ClientCredentials('{0}', '{1}', '{2}', {3})".format(
            self.token_url, self.username, self.password, addition_args_str
        )


class OAuth2AuthorizationCode(requests.auth.AuthBase):
    """
    Authorization Code Grant

    Describes an OAuth 2 authorization code (also called access code) flow requests authentication.

    Request a code with client browser, then request a token using this code.
    Store the token and use it for subsequent valid requests.

    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.1
    """

    def __init__(self, authorization_url, token_url, **kwargs):
        """
        :param authorization_url: OAuth 2 authorization URL.
        :param token_url: OAuth 2 token URL.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 code will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a code or a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a code is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received code is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param response_type: Value of the response_type query parameter if not already provided in authorization URL.
        code by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param code_field_name: Field name containing the code. code by default.
        :param username: User name in case basic authentication should be used to retrieve token.
        :param password: User password in case basic authentication should be used to retrieve token.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL and as body parameters in the token URL.
        Usual parameters are:
        * client_id: Corresponding to your Application ID (in Microsoft Azure app portal)
        * client_secret: If client is not authenticated with the authorization server
        * nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        """
        self.authorization_url = authorization_url
        if not self.authorization_url:
            raise Exception('Authorization URL is mandatory.')

        self.token_url = token_url
        if not self.token_url:
            raise Exception('Token URL is mandatory.')
        self.kwargs = kwargs

        extra_parameters = dict(kwargs)
        self.header_name = extra_parameters.pop('header_name', None) or 'Authorization'
        self.header_value = extra_parameters.pop('header_value', None) or 'Bearer {token}'
        if '{token}' not in self.header_value:
            raise Exception('header_value parameter must contains {token}.')

        redirect_uri_endpoint = extra_parameters.pop('redirect_uri_endpoint', None) or ''
        redirect_uri_port = int(extra_parameters.pop('redirect_uri_port', None) or 5000)

        self.token_field_name = extra_parameters.pop('token_field_name', None) or 'access_token'

        # Time is expressed in seconds
        self.timeout = int(extra_parameters.pop('timeout', None) or 60)
        # Time is expressed in milliseconds
        success_display_time = int(extra_parameters.pop('success_display_time', None) or 1)
        # Time is expressed in milliseconds
        failure_display_time = int(extra_parameters.pop('failure_display_time', None) or 5000)

        username = extra_parameters.pop('username', None)
        password = extra_parameters.pop('password', None)
        self.auth = (username, password) if username and password else None

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.2
        code_field_name = extra_parameters.pop('code_field_name', 'code')
        if _contains_query_parameter(self.authorization_url, 'response_type'):
            extra_parameters.pop('response_type', None)  # Ensure provided value will not be overridden
        else:
            # As described in https://tools.ietf.org/html/rfc6749#section-4.1.1
            extra_parameters.setdefault('response_type', 'code')

        redirect_uri = 'http://localhost:{0}/{1}'.format(redirect_uri_port, redirect_uri_endpoint)
        authorization_url_without_nonce = _add_parameters(self.authorization_url, extra_parameters)
        authorization_url_without_nonce, nonce = _pop_parameter(authorization_url_without_nonce, 'nonce')
        self.state = sha512(authorization_url_without_nonce.encode('unicode_escape')).hexdigest()
        custom_code_parameters = {'state': self.state, 'redirect_uri': redirect_uri}
        if nonce:
            custom_code_parameters['nonce'] = nonce
        code_grant_url = _add_parameters(authorization_url_without_nonce, custom_code_parameters)
        self.code_grant_details = oauth2_authentication_responses_server.GrantDetails(
            code_grant_url,
            code_field_name,
            self.timeout,
            success_display_time,
            failure_display_time,
            redirect_uri_port
        )

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.3
        self.token_data = {
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
        }
        self.token_data.update(extra_parameters)

    def __call__(self, r):
        token = OAuth2.token_cache.get_token(self.state, self.request_new_token)
        r.headers[self.header_name] = self.header_value.format(token=token)
        return r

    def request_new_token(self):
        # Request code
        state, code = oauth2_authentication_responses_server.request_new_grant(self.code_grant_details)

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.3
        self.token_data['code'] = code
        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.4
        token, expires_in = request_new_grant_with_post(
            self.token_url, self.token_data, self.token_field_name, self.timeout, auth=self.auth
        )
        # Handle both Access and Bearer tokens
        return (self.state, token, expires_in) if expires_in else (self.state, token)

    def __str__(self):
        addition_args_str = ', '.join(["{0}='{1}'".format(key, value) for key, value in self.kwargs.items()])
        return "OAuth2AuthorizationCode('{0}', '{1}', {2})".format(
            self.authorization_url, self.token_url, addition_args_str
        )


class OAuth2Implicit(requests.auth.AuthBase):
    """
    Implicit Grant

    Describes an OAuth 2 implicit flow requests authentication.

    Request a token with client browser.
    Store the token and use it for subsequent valid requests.

    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.2
    """

    def __init__(self, authorization_url, **kwargs):
        """
        :param authorization_url: OAuth 2 authorization URL.
        :param response_type: Value of the response_type query parameter if not already provided in authorization URL.
        token by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * client_id: Corresponding to your Application ID (in Microsoft Azure app portal)
        * nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        self.authorization_url = authorization_url
        if not self.authorization_url:
            raise Exception('Authorization URL is mandatory.')
        self.kwargs = kwargs

        extra_parameters = dict(kwargs)
        self.header_name = extra_parameters.pop('header_name', None) or 'Authorization'
        self.header_value = extra_parameters.pop('header_value', None) or 'Bearer {token}'
        if '{token}' not in self.header_value:
            raise Exception('header_value parameter must contains {token}.')

        redirect_uri_endpoint = extra_parameters.pop('redirect_uri_endpoint', None) or ''
        redirect_uri_port = int(extra_parameters.pop('redirect_uri_port', None) or 5000)
        # Time is expressed in seconds
        timeout = int(extra_parameters.pop('timeout', None) or 60)
        # Time is expressed in milliseconds
        success_display_time = int(extra_parameters.pop('success_display_time', None) or 1)
        # Time is expressed in milliseconds
        failure_display_time = int(extra_parameters.pop('failure_display_time', None) or 5000)
        # As described in https://tools.ietf.org/html/rfc6749#section-4.2.2
        token_field_name = extra_parameters.pop('token_field_name', 'access_token')
        if _contains_query_parameter(self.authorization_url, 'response_type'):
            extra_parameters.pop('response_type', None)  # Ensure provided value will not be overridden
        else:
            # As described in https://tools.ietf.org/html/rfc6749#section-4.2.1
            extra_parameters.setdefault('response_type', 'token')

        redirect_uri = 'http://localhost:{0}/{1}'.format(redirect_uri_port, redirect_uri_endpoint)
        authorization_url_without_nonce = _add_parameters(self.authorization_url, extra_parameters)
        authorization_url_without_nonce, nonce = _pop_parameter(authorization_url_without_nonce, 'nonce')
        self.state = sha512(authorization_url_without_nonce.encode('unicode_escape')).hexdigest()
        custom_parameters = {'state': self.state, 'redirect_uri': redirect_uri}
        if nonce:
            custom_parameters['nonce'] = nonce
        grant_url = _add_parameters(authorization_url_without_nonce, custom_parameters)
        self.grant_details = oauth2_authentication_responses_server.GrantDetails(
            grant_url,
            token_field_name,
            timeout,
            success_display_time,
            failure_display_time,
            redirect_uri_port
        )

    def __call__(self, r):
        token = OAuth2.token_cache.get_token(
            self.state, oauth2_authentication_responses_server.request_new_grant, self.grant_details
        )
        r.headers[self.header_name] = self.header_value.format(token=token)
        return r

    def __str__(self):
        addition_args_str = ', '.join(["{0}='{1}'".format(key, value) for key, value in self.kwargs.items()])
        return "OAuth2Implicit('{0}', {1})".format(self.authorization_url, addition_args_str)


class AzureActiveDirectoryImplicit(OAuth2Implicit):
    """
    Describes an Azure Active Directory (OAuth 2) "Access Token" requests authentication.
    https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens
    """

    def __init__(self, tenant_id, client_id, **kwargs):
        """
        :param tenant_id: Microsoft Tenant Identifier (formatted as an Universal Unique Identifier)
        :param client_id: Microsoft Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        token by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        OAuth2Implicit.__init__(
            self,
            'https://login.microsoftonline.com/{0}/oauth2/authorize'.format(tenant_id),
            client_id=client_id,
            nonce=kwargs.pop('nonce', None) or str(uuid.uuid4()),
            **kwargs
        )


class AzureActiveDirectoryImplicitIdToken(OAuth2Implicit):
    """
    Describes an Azure Active Directory (OpenID Connect) "ID Token" requests authentication.
    https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
    """

    def __init__(self, tenant_id, client_id, **kwargs):
        """
        :param tenant_id: Microsoft Tenant Identifier (formatted as an Universal Unique Identifier)
        :param client_id: Microsoft Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        id_token by default.
        :param token_field_name: Name of the expected field containing the token.
        id_token by default.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        OAuth2Implicit.__init__(
            self,
            'https://login.microsoftonline.com/{0}/oauth2/authorize'.format(tenant_id),
            client_id=client_id,
            response_type=kwargs.pop('response_type', 'id_token'),
            token_field_name=kwargs.pop('token_field_name', 'id_token'),
            nonce=kwargs.pop('nonce', None) or str(uuid.uuid4()),
            **kwargs
        )


class OktaImplicit(OAuth2Implicit):
    """
    Describes an OKTA (OAuth 2) "Access Token" implicit flow requests authentication.
    """

    def __init__(self, instance, client_id, **kwargs):
        """
        :param instance: OKTA instance (like "testserver.okta-emea.com")
        :param client_id: Microsoft Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        token by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param authorization_server: OKTA authorization server
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        Request ['openid', 'profile', 'email'] by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        authorization_server = kwargs.pop('authorization_server', None)
        scopes = kwargs.pop('scope', None) or ['openid', 'profile', 'email']
        kwargs['scope'] = ' '.join(scopes) if isinstance(scopes, list) else scopes
        OAuth2Implicit.__init__(
            self,
            'https://{okta_instance}/oauth2{okta_auth_server}/v1/authorize'.format(
                okta_instance=instance,
                okta_auth_server="/" + authorization_server if authorization_server else ""
            ),
            client_id=client_id,
            nonce=kwargs.pop('nonce', None) or str(uuid.uuid4()),
            **kwargs
        )


class OktaImplicitIdToken(OAuth2Implicit):
    """
    Describes an OKTA (OpenID Connect) "ID Token" implicit flow requests authentication.
    """

    def __init__(self, instance, client_id, **kwargs):
        """
        :param instance: OKTA instance (like "testserver.okta-emea.com")
        :param client_id: Microsoft Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        id_token by default.
        :param token_field_name: Name of the expected field containing the token.
        id_token by default.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param authorization_server: OKTA authorization server
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        Request ['openid', 'profile', 'email'] by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        authorization_server = kwargs.pop('authorization_server', None)
        scopes = kwargs.pop('scope', None) or ['openid', 'profile', 'email']
        kwargs['scope'] = ' '.join(scopes) if isinstance(scopes, list) else scopes
        OAuth2Implicit.__init__(
            self,
            'https://{okta_instance}/oauth2{okta_auth_server}/v1/authorize'.format(
                okta_instance=instance,
                okta_auth_server="/" + authorization_server if authorization_server else ""
            ),
            client_id=client_id,
            response_type=kwargs.pop('response_type', 'id_token'),
            token_field_name=kwargs.pop('token_field_name', 'id_token'),
            nonce=kwargs.pop('nonce', None) or str(uuid.uuid4()),
            **kwargs
        )


class HeaderApiKey(requests.auth.AuthBase):
    """Describes an API Key requests authentication."""

    def __init__(self, api_key, header_name=None):
        """
        :param api_key: The API key that will be sent.
        :param header_name: Name of the header field. "X-API-Key" by default.
        """
        self.api_key = api_key
        if not api_key:
            raise Exception('API Key is mandatory.')
        self.header_name = header_name or 'X-API-Key'

    def __call__(self, r):
        r.headers[self.header_name] = self.api_key
        return r

    def __str__(self):
        return "HeaderApiKey('{0}', '{1}')".format(self.api_key, self.header_name)


class QueryApiKey(requests.auth.AuthBase):
    """Describes an API Key requests authentication."""

    def __init__(self, api_key, query_parameter_name=None):
        """
        :param api_key: The API key that will be sent.
        :param query_parameter_name: Name of the query parameter. "api_key" by default.
        """
        self.api_key = api_key
        if not api_key:
            raise Exception('API Key is mandatory.')
        self.query_parameter_name = query_parameter_name or 'api_key'

    def __call__(self, r):
        r.url = _add_parameters(r.url, {self.query_parameter_name: self.api_key})
        return r

    def __str__(self):
        return "QueryApiKey('{0}', '{1}')".format(self.api_key, self.query_parameter_name)


class Basic(requests.auth.HTTPBasicAuth):
    """Describes a basic requests authentication."""

    def __init__(self, username, password):
        requests.auth.HTTPBasicAuth.__init__(self, username, password)

    def __str__(self):
        return "Basic('{0}', '{1}')".format(self.username, self.password)


class NTLM:
    """Describes a NTLM requests authentication."""

    def __init__(self, username=None, password=None):
        """
        :param username: Mandatory if requests_negotiate_sspi module is not installed.
        :param password: Mandatory if requests_negotiate_sspi module is not installed.
        """
        self.username = username
        self.password = password
        if not username and not password:
            try:
                import requests_negotiate_sspi
                self.auth = requests_negotiate_sspi.HttpNegotiateAuth()
            except ImportError:
                raise Exception('NTLM authentication requires requests_negotiate_sspi module.')
        else:
            if not username:
                raise Exception('NTLM authentication requires "username" to be provided in security_details.')
            if not password:
                raise Exception('NTLM authentication requires "password" to be provided in security_details.')
            try:
                import requests_ntlm
                self.auth = requests_ntlm.HttpNtlmAuth(username, password)
            except ImportError:
                raise Exception('NTLM authentication requires requests_ntlm module.')

    def __call__(self, r):
        self.auth.__call__(r)
        return r

    def __str__(self):
        if self.username and self.password:
            return "NTLM('{0}', '{1}')".format(self.username, self.password)
        return "NTLM()"


class Auths(requests.auth.AuthBase):
    """Authentication using multiple authentication methods."""

    def __init__(self, *authentication_modes):
        self.authentication_modes = authentication_modes

    def __call__(self, r):
        for authentication_mode in self.authentication_modes:
            authentication_mode.__call__(r)
        return r

    def __str__(self):
        return "Auths(" + ", ".join(map(str, self.authentication_modes)) + ")"
