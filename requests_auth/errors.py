class AuthenticationFailed(Exception):
    """ User was not authenticated. """

    def __init__(self):
        Exception.__init__(self, "User was not authenticated.")


class TimeoutOccurred(Exception):
    """ No response within timeout interval. """

    def __init__(self, timeout):
        Exception.__init__(
            self,
            "User authentication was not received within {0} seconds.".format(timeout),
        )


class InvalidToken(Exception):
    """ Token is invalid. """

    def __init__(self, token_name):
        Exception.__init__(self, "{0} is invalid.".format(token_name))


class GrantNotProvided(Exception):
    """ Grant was not provided. """

    def __init__(self, grant_name, dictionary_without_grant):
        Exception.__init__(
            self,
            "{0} not provided within {1}.".format(grant_name, dictionary_without_grant),
        )


class StateNotProvided(Exception):
    """ State was not provided. """

    def __init__(self, dictionary_without_state):
        Exception.__init__(
            self, "state not provided within {0}.".format(dictionary_without_state)
        )


class TokenExpiryNotProvided(Exception):
    """ Token expiry was not provided. """

    def __init__(self, token_body):
        Exception.__init__(
            self, "Expiry (exp) is not provided in {0}.".format(token_body)
        )
