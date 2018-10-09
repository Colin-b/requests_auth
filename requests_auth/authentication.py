import sys
from hashlib import sha512
import uuid
import requests
import requests.auth

from requests_auth import oauth2_authentication_responses_server, oauth2_tokens

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


def _get_query_parameter(url, param_name):
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string)
    all_values = query_params.get(param_name)
    return all_values[0] if all_values else None


class OAuth2(requests.auth.AuthBase):
    """
    Describes an OAuth 2 requests authentication.
    """

    token_cache = oauth2_tokens.TokenMemoryCache()

    def __init__(self, authorization_url, **kwargs):
        """
        :param authorization_url: OAuth 2 authorization URL.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param redirect_uri_port_availability_timeout:  The maximum amount of seconds to wait for the
        redirect_uri_port to become available.
        Wait for 2 seconds maximum by default.
        :param token_reception_timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param token_reception_success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param token_reception_failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Common parameters are:
        * client_id: Corresponding to your Application ID (in Microsoft Azure app portal)
        * response_type: id_token for Microsoft
        * nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        """
        self.authorization_url = authorization_url
        if not self.authorization_url:
            raise Exception('Authorization URL is mandatory.')
        self.kwargs = kwargs
        self.extra_parameters = dict(kwargs)
        self.redirect_uri_endpoint = self.extra_parameters.pop('redirect_uri_endpoint', None) or ''
        self.redirect_uri_port = int(self.extra_parameters.pop('redirect_uri_port', None) or 5000)
        # Time is expressed in seconds
        self.redirect_uri_port_availability_timeout = float(self.extra_parameters.pop('redirect_uri_port_availability_timeout', None) or 2)
        # Time is expressed in seconds
        self.token_reception_timeout = int(self.extra_parameters.pop('token_reception_timeout', None) or 60)
        # Time is expressed in milliseconds
        self.token_reception_success_display_time = int(self.extra_parameters.pop('token_reception_success_display_time', None) or 1)
        # Time is expressed in milliseconds
        self.token_reception_failure_display_time = int(self.extra_parameters.pop('token_reception_failure_display_time', None) or 5000)
        self.header_name = self.extra_parameters.pop('header_name', None) or 'Authorization'
        self.header_value = self.extra_parameters.pop('header_value', None) or 'Bearer {token}'
        if '{token}' not in self.header_value:
            raise Exception('header_value parameter must contains {token}.')

        self.redirect_uri = 'http://localhost:{0}/{1}'.format(self.redirect_uri_port, self.redirect_uri_endpoint)
        unique_token_provider_url = _add_parameters(self.authorization_url, self.extra_parameters)
        unique_token_provider_url, nonce = _pop_parameter(unique_token_provider_url, 'nonce')
        self.unique_token_provider_identifier = sha512(unique_token_provider_url.encode('unicode_escape')).hexdigest()
        custom_parameters = {'state': self.unique_token_provider_identifier, 'redirect_uri': self.redirect_uri}
        if nonce:
            custom_parameters['nonce'] = nonce
        self.full_url = _add_parameters(unique_token_provider_url, custom_parameters)
        # As described in https://tools.ietf.org/html/rfc6749#section-4.2.1
        self.token_name = _get_query_parameter(self.full_url, 'response_type') or 'token'

    def __call__(self, r):
        token = OAuth2.token_cache.get_token(self.unique_token_provider_identifier,
                                             oauth2_authentication_responses_server.request_new_token,
                                             self)
        r.headers[self.header_name] = self.header_value.format(token=token)
        return r

    def __str__(self):
        addition_args_str = ', '.join(["{0}='{1}'".format(key, value)
                                       for key, value in self.kwargs.items()])
        return "authentication.OAuth2('{0}', {1})".format(self.authorization_url, addition_args_str)


class AzureActiveDirectory(OAuth2):
    """
    Describes an Azure Active Directory (Microsoft OAuth 2) requests authentication.
    """

    def __init__(self, tenant_id, client_id, **kwargs):
        """
        :param tenant_id: Microsoft Tenant Identifier (formatted as an Universal Unique Identifier)
        :param client_id: Microsoft Application Identifier (formatted as an Universal Unique Identifier)
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param redirect_uri_port_availability_timeout:  The maximum amount of seconds to wait for the
        redirect_uri_port to become available.
        Wait for 2 seconds maximum by default.
        :param token_reception_timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param token_reception_success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param token_reception_failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        """
        OAuth2.__init__(self,
                        'https://login.microsoftonline.com/{0}/oauth2/authorize'.format(tenant_id),
                        client_id=client_id,
                        response_type='id_token',
                        nonce=kwargs.pop('nonce', None) or str(uuid.uuid4()),
                        **kwargs)


class Okta(OAuth2):
    """
    Describes an OKTA (OAuth 2) requests authentication.
    """

    def __init__(self, instance, client_id, **kwargs):
        """
        :param instance: OKTA instance (like "testserver.okta-emea.com")
        :param client_id: Microsoft Application Identifier (formatted as an Universal Unique Identifier)
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param authorization_server: OKTA authorization server
        :param scope: Scope parameter sent in query.
        :param scopes: List of scopes sent in query. Only valid if scope is not provided.
        Request ['openid', 'profile', 'email'] by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param redirect_uri_port_availability_timeout:  The maximum amount of seconds to wait for the
        redirect_uri_port to become available.
        Wait for 2 seconds maximum by default.
        :param token_reception_timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param token_reception_success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param token_reception_failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        """
        authorization_server = kwargs.pop('authorization_server', None)
        if 'scope' not in kwargs:
            kwargs['scope'] = ' '.join(kwargs.pop('scopes', ['openid', 'profile', 'email']))
        OAuth2.__init__(self,
                        'https://{okta_instance}/oauth2{okta_auth_server}/v1/authorize'.format(
                            okta_instance=instance,
                            okta_auth_server="/" + authorization_server if authorization_server else ""
                        ),
                        client_id=client_id,
                        response_type='id_token',
                        nonce=kwargs.pop('nonce', None) or str(uuid.uuid4()),
                        **kwargs)


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
        return "authentication.HeaderApiKey('{0}', '{1}')".format(self.api_key, self.header_name)


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
        return "authentication.QueryApiKey('{0}', '{1}')".format(self.api_key, self.query_parameter_name)


class Basic(requests.auth.HTTPBasicAuth):
    """Describes a basic requests authentication."""

    def __init__(self, username, password):
        requests.auth.HTTPBasicAuth.__init__(self, username, password)

    def __str__(self):
        return "authentication.Basic('{0}', '{1}')".format(self.username, self.password)


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
            return "authentication.NTLM('{0}', '{1}')".format(self.username, self.password)
        return "authentication.NTLM()"


class Auths(requests.auth.AuthBase):
    """Authentication using multiple authentication methods."""

    def __init__(self, *authentication_modes):
        self.authentication_modes = authentication_modes

    def __call__(self, r):
        for authentication_mode in self.authentication_modes:
            authentication_mode.__call__(r)
        return r

    def __str__(self):
        return "authentication.Auths(" + ", ".join(map(str, self.authentication_modes)) + ")"
