from json import JSONDecodeError

from requests import Response


class AuthenticationFailed(Exception):
    """ User was not authenticated. """

    def __init__(self):
        Exception.__init__(self, "User was not authenticated.")


class TimeoutOccurred(Exception):
    """ No response within timeout interval. """

    def __init__(self, timeout: float):
        Exception.__init__(
            self, f"User authentication was not received within {timeout} seconds."
        )


class InvalidToken(Exception):
    """ Token is invalid. """

    def __init__(self, token_name: str):
        Exception.__init__(self, f"{token_name} is invalid.")


class GrantNotProvided(Exception):
    """ Grant was not provided. """

    def __init__(self, grant_name: str, dictionary_without_grant: dict):
        Exception.__init__(
            self, f"{grant_name} not provided within {dictionary_without_grant}."
        )


class InvalidGrantRequest(Exception):
    """
    If the request failed client authentication or is invalid, the authorization server returns an error response as described in https://tools.ietf.org/html/rfc6749#section-5.2
    """

    errors = {
        "invalid_request": "The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.",
        "invalid_client": 'Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).  The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported.  If the client attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.',
        "invalid_grant": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
        "unauthorized_client": "The authenticated client is not authorized to use this authorization grant type.",
        "unsupported_grant_type": "The authorization grant type is not supported by the authorization server.",
        "invalid_scope": "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.",
    }

    def __init__(self, response: Response):
        Exception.__init__(self, InvalidGrantRequest.to_message(response))

    @staticmethod
    def to_message(response: Response) -> str:
        """
        Handle response as described in https://tools.ietf.org/html/rfc6749#section-5.2
        """
        try:
            content = response.json()
            if "error" in content:
                error = content.pop("error", None)
                error_description = content.pop(
                    "error_description", None
                ) or InvalidGrantRequest.errors.get(error)
                message = f"{error}: {error_description}"
                if "error_uri" in content:
                    message += (
                        f"\nMore information can be found on {content.pop('error_uri')}"
                    )
                if content:
                    message += f"\nAdditional information: {content}"
            else:
                message = response.text
        except JSONDecodeError:
            message = response.text
        return message


class StateNotProvided(Exception):
    """ State was not provided. """

    def __init__(self, dictionary_without_state: dict):
        Exception.__init__(
            self, f"state not provided within {dictionary_without_state}."
        )


class TokenExpiryNotProvided(Exception):
    """ Token expiry was not provided. """

    def __init__(self, token_body: dict):
        Exception.__init__(self, f"Expiry (exp) is not provided in {token_body}.")
