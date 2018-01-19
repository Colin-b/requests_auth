class PortNotAvailable(Exception):
    """ Port is already taken. """
    def __init__(self, port, *args, **kwargs):
        Exception.__init__(self, 'The port {0} is not available.'.format(port))


class AuthenticationFailed(Exception):
    """ User was not authenticated. """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, 'User was not authenticated.')


class TimeoutOccurred(Exception):
    """ No response within timeout interval. """
    def __init__(self, timeout, *args, **kwargs):
        Exception.__init__(self, 'User authentication was not received within {0} seconds.'.format(timeout))


class InvalidToken(Exception):
    """ Token is invalid. """
    def __init__(self, token_name, *args, **kwargs):
        Exception.__init__(self, '{0} is invalid.'.format(token_name))


class TokenNotProvided(Exception):
    """ Token was not provided. """
    def __init__(self, token_name, dictionary_without_token, *args, **kwargs):
        Exception.__init__(self, '{0} not provided within {1}.'.format(token_name, dictionary_without_token))


class StateNotProvided(Exception):
    """ State was not provided. """
    def __init__(self, dictionary_without_state, *args, **kwargs):
        Exception.__init__(self, 'state not provided within {0}.'.format(dictionary_without_state))


class TokenExpiryNotProvided(Exception):
    """ Token expiry was not provided. """
    def __init__(self, token_body, *args, **kwargs):
        Exception.__init__(self, 'Expiry (exp) is not provided in {0}.'.format(token_body))
