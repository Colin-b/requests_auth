from urllib.parse import parse_qs, urlsplit, urlunsplit, urlencode

import requests
import requests.auth


class SupportMultiAuth:
    """Inherit from this class to be able to use your class with requests_auth provided authentication classes."""

    def __add__(self, other):
        if isinstance(other, _MultiAuth):
            return _MultiAuth(self, *other.authentication_modes)
        return _MultiAuth(self, other)

    def __and__(self, other):
        if isinstance(other, _MultiAuth):
            return _MultiAuth(self, *other.authentication_modes)
        return _MultiAuth(self, other)


class HeaderApiKey(requests.auth.AuthBase, SupportMultiAuth):
    """Describes an API Key requests authentication."""

    def __init__(self, api_key: str, header_name: str = None):
        """
        :param api_key: The API key that will be sent.
        :param header_name: Name of the header field. "X-API-Key" by default.
        """
        self.api_key = api_key
        if not api_key:
            raise Exception("API Key is mandatory.")
        self.header_name = header_name or "X-API-Key"

    def __call__(self, r):
        r.headers[self.header_name] = self.api_key
        return r


class QueryApiKey(requests.auth.AuthBase, SupportMultiAuth):
    """Describes an API Key requests authentication."""

    def __init__(self, api_key: str, query_parameter_name: str = None):
        """
        :param api_key: The API key that will be sent.
        :param query_parameter_name: Name of the query parameter. "api_key" by default.
        """
        self.api_key = api_key
        if not api_key:
            raise Exception("API Key is mandatory.")
        self.query_parameter_name = query_parameter_name or "api_key"

    def __call__(self, r):
        r.url = _add_parameters(r.url, {self.query_parameter_name: self.api_key})
        return r


class Basic(requests.auth.HTTPBasicAuth, SupportMultiAuth):
    """Describes a basic requests authentication."""

    def __init__(self, username: str, password: str):
        requests.auth.HTTPBasicAuth.__init__(self, username, password)


class NTLM(requests.auth.AuthBase, SupportMultiAuth):
    """Describes a NTLM requests authentication."""

    def __init__(self, username: str = None, password: str = None):
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
                raise Exception(
                    "NTLM authentication requires requests_negotiate_sspi module."
                )
        else:
            if not username:
                raise Exception(
                    'NTLM authentication requires "username" to be provided in security_details.'
                )
            if not password:
                raise Exception(
                    'NTLM authentication requires "password" to be provided in security_details.'
                )
            try:
                import requests_ntlm

                self.auth = requests_ntlm.HttpNtlmAuth(username, password)
            except ImportError:
                raise Exception("NTLM authentication requires requests_ntlm module.")

    def __call__(self, r):
        self.auth.__call__(r)
        return r


class _MultiAuth(requests.auth.AuthBase):
    """Authentication using multiple authentication methods."""

    def __init__(self, *authentication_modes):
        self.authentication_modes = authentication_modes

    def __call__(self, r):
        for authentication_mode in self.authentication_modes:
            authentication_mode.__call__(r)
        return r

    def __add__(self, other):
        if isinstance(other, _MultiAuth):
            return _MultiAuth(*self.authentication_modes, *other.authentication_modes)
        return _MultiAuth(*self.authentication_modes, other)

    def __and__(self, other):
        if isinstance(other, _MultiAuth):
            return _MultiAuth(*self.authentication_modes, *other.authentication_modes)
        return _MultiAuth(*self.authentication_modes, other)


def _add_parameters(initial_url: str, extra_parameters: dict) -> str:
    """
    Add parameters to an URL and return the new URL.

    :param initial_url:
    :param extra_parameters: dictionary of parameters name and value.
    :return: the new URL containing parameters.
    """
    scheme, netloc, path, query_string, fragment = urlsplit(initial_url)
    query_params = parse_qs(query_string)
    query_params.update(
        {
            parameter_name: [parameter_value]
            for parameter_name, parameter_value in extra_parameters.items()
        }
    )

    new_query_string = urlencode(query_params, doseq=True)

    return urlunsplit((scheme, netloc, path, new_query_string, fragment))
