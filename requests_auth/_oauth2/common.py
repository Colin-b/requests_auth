from urllib.parse import parse_qs, urlsplit, urlunsplit, urlencode
from typing import Optional

import requests.auth

from requests_auth._errors import InvalidGrantRequest, GrantNotProvided
from requests_auth._oauth2.browser import DisplaySettings
from requests_auth._oauth2.tokens import TokenMemoryCache


def _pop_parameter(url: str, query_parameter_name: str) -> (str, Optional[str]):
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

    return (
        urlunsplit((scheme, netloc, path, new_query_string, fragment)),
        parameter_value,
    )


def _get_query_parameter(url: str, param_name: str) -> Optional[str]:
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string)
    all_values = query_params.get(param_name)
    return all_values[0] if all_values else None


def _content_from_response(response: requests.Response) -> dict:
    content_type = response.headers.get("content-type")
    if content_type == "text/html; charset=utf-8":
        return {
            key_values[0]: key_values[1]
            for key_value in response.text.split("&")
            if (key_values := key_value.split("=")) and len(key_values) == 2
        }
    return response.json()


def request_new_grant_with_post(
    url: str, data, grant_name: str, timeout: float, session: requests.Session
) -> (str, int, str):
    with session:
        response = session.post(url, data=data, timeout=timeout)
        if not response:
            # As described in https://tools.ietf.org/html/rfc6749#section-5.2
            raise InvalidGrantRequest(response)

        content = _content_from_response(response)
    token = content.get(grant_name)
    if not token:
        raise GrantNotProvided(grant_name, content)
    return token, content.get("expires_in"), content.get("refresh_token")


class OAuth2:
    token_cache = TokenMemoryCache()
    display = DisplaySettings()
