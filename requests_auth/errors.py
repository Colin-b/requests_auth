class AuthenticationFailed(Exception):
    """ User was not authenticated. """

    def __init__(self):
        Exception.__init__(self, "User was not authenticated.")


class TimeoutOccurred(Exception):
    """ No response within timeout interval. """

    def __init__(self, timeout: int):
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
