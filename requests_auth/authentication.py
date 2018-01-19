import sys
from hashlib import sha512
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

    def __init__(self,
                 authorization_url,
                 redirect_uri_endpoint=None,
                 redirect_uri_port=None,
                 redirect_uri_port_availability_timeout=None,
                 token_reception_timeout=None,
                 token_reception_success_display_time=None,
                 token_reception_failure_display_time=None,
                 **kwargs):
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
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Common parameters are:
        * client_id: Corresponding to your Application ID (in Microsoft Azure app portal)
        * response_type: id_token for Microsoft
        * nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        """
        from requests_auth.oauth2_authentication_responses_server import (
            DEFAULT_SERVER_PORT,
            DEFAULT_TOKEN_NAME,
            DEFAULT_PORT_AVAILABILITY_TIMEOUT,
            DEFAULT_AUTHENTICATION_TIMEOUT,
            DEFAULT_SUCCESS_DISPLAY_TIME,
            DEFAULT_FAILURE_DISPLAY_TIME
        )
        self.authorization_url = authorization_url
        if not self.authorization_url:
            raise Exception('Authorization URL is mandatory.')
        self.redirect_uri_endpoint = redirect_uri_endpoint or ''
        self.redirect_uri_port = int(redirect_uri_port or DEFAULT_SERVER_PORT)
        self.redirect_uri_port_availability_timeout = float(redirect_uri_port_availability_timeout or
                                                            DEFAULT_PORT_AVAILABILITY_TIMEOUT)
        self.redirect_uri = 'http://localhost:{0}/{1}'.format(self.redirect_uri_port, self.redirect_uri_endpoint)
        self.kwargs = kwargs
        unique_token_provider_url = _add_parameters(self.authorization_url, self.kwargs)
        unique_token_provider_url, nonce = _pop_parameter(unique_token_provider_url, 'nonce')
        self.unique_token_provider_identifier = sha512(unique_token_provider_url.encode('unicode_escape')).hexdigest()
        custom_parameters = {
            'state': self.unique_token_provider_identifier,
            'redirect_uri': self.redirect_uri,

            # TODO Handle GET to be able to get rid of this HACK (not working with every OAUTH2 provider anyway)
            # Force Form Post as get is only providing token in anchor and anchor is not provided to server
            # (interpreted on client side only)
            'response_mode': 'form_post',
        }
        if nonce:
            custom_parameters['nonce'] = nonce
        self.full_url = _add_parameters(unique_token_provider_url, custom_parameters)
        self.token_name = _get_query_parameter(self.full_url, 'response_type') or DEFAULT_TOKEN_NAME
        self.token_reception_timeout = int(token_reception_timeout or DEFAULT_AUTHENTICATION_TIMEOUT)
        self.token_reception_success_display_time = int(token_reception_success_display_time or
                                                        DEFAULT_SUCCESS_DISPLAY_TIME)
        self.token_reception_failure_display_time = int(token_reception_failure_display_time or
                                                        DEFAULT_FAILURE_DISPLAY_TIME)

    def __call__(self, r):
        token = OAuth2.token_cache.get_token(self.unique_token_provider_identifier,
                                             oauth2_authentication_responses_server.request_new_token,
                                             self)
        r.headers['Bearer'] = token
        return r

    def __str__(self):
        addition_args_str = ', '.join(["{0}='{1}'".format(key, value)
                                       for key, value in self.kwargs.items()])
        return "authentication.OAuth2('{0}', redirect_uri_endpoint='{1}', redirect_uri_port={2}, " \
               "redirect_uri_port_availability_timeout={3}, token_reception_timeout={4}, " \
               "token_reception_success_display_time={5}, token_reception_failure_display_time={6}, {7})".format(
            self.authorization_url, self.redirect_uri_endpoint, self.redirect_uri_port,
            self.redirect_uri_port_availability_timeout, self.token_reception_timeout,
            self.token_reception_success_display_time, self.token_reception_failure_display_time, addition_args_str)


class MicrosoftOAuth2(OAuth2):
    """
    Describes a Microsoft OAuth 2 requests authentication.
    """
    def __init__(self,
                 tenant_id,
                 client_id,
                 nonce,
                 redirect_uri_endpoint=None,
                 redirect_uri_port=None,
                 redirect_uri_port_availability_timeout=None,
                 token_reception_timeout=None,
                 token_reception_success_display_time=None,
                 token_reception_failure_display_time=None,
                 **kwargs):
        """
        :param tenant_id: Microsoft Tenant Identifier (formatted as 45239d18-c68c-4c47-8bdd-ce71ea1d50cd)
        :param client_id: Microsoft Application Identifier (formatted as 45239d18-c68c-4c47-8bdd-ce71ea1d50cd)
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as 7362CAEA-9CA5-4B43-9BA3-34D7C303EBA7)
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
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        """
        OAuth2.__init__(self,
                        'https://login.microsoftonline.com/{0}/oauth2/authorize'.format(tenant_id),
                        redirect_uri_endpoint,
                        redirect_uri_port,
                        redirect_uri_port_availability_timeout,
                        token_reception_timeout,
                        token_reception_success_display_time,
                        token_reception_failure_display_time,
                        client_id=client_id,
                        response_type='id_token',
                        nonce=nonce)


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
    def __init__(self, authentication_modes):
        self.authentication_modes = authentication_modes

    def __call__(self, r):
        for authentication_mode in self.authentication_modes:
            authentication_mode.__call__(r)
        return r

    def __str__(self):
        return "authentication.Auths([" + ", ".join(map(str, self.authentication_modes)) + "])"
