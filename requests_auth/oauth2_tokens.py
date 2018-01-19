import base64
import json
import os
import datetime
import threading
import logging
from requests_auth.errors import *

logger = logging.getLogger(__name__)


def decode_base64(base64_encoded_string):
    """
    Decode base64, padding being optional.

    :param base64_encoded_string: Base64 data as an ASCII byte string
    :returns: The decoded byte string.
    """
    missing_padding = len(base64_encoded_string) % 4
    if missing_padding != 0:
        base64_encoded_string += '=' * (4 - missing_padding)
    return base64.b64decode(base64_encoded_string).decode('unicode_escape')


def is_expired(expiry):
    return datetime.datetime.utcfromtimestamp(expiry) < datetime.datetime.utcnow()


class TokenMemoryCache:
    """
    Class to manage tokens using memory storage.
    """

    def __init__(self):
        self.tokens = {}
        self.forbid_concurrent_cache_access = threading.Lock()
        self.forbid_concurrent_missing_token_function_call = threading.Lock()

    def add_token(self, key, token):
        """
        Set the bearer token and save it
        :param key: key identifier of the token
        :param token: value
        :raise InvalidToken: In case token is invalid.
        """
        if not token:
            raise InvalidToken(token)
        with self.forbid_concurrent_cache_access:
            header, body, other = token.split('.')
            body = json.loads(decode_base64(body))
            if 'exp' not in body:
                raise TokenExpiryNotProvided(body)
            expiry = body['exp']
            self.tokens[key] = token, expiry
            self._save_tokens()
            logger.debug('Inserting token expiring on {0} (UTC) with "{1}" key: {2}'.format(
                datetime.datetime.utcfromtimestamp(expiry), key, token))

    def get_token(self, key, on_missing_token=None, *on_missing_token_args):
        """
        Return the bearer token.
        :param key: key identifier of the token
        :param on_missing_token: function to call when token is expired or missing (returning token and expiry tuple)
        :param on_missing_token_args: arguments of the function
        :return: the token
        :raise AuthenticationFailed: in case token cannot be retrieved.
        """
        logger.debug('Retrieving token with "{0}" key.'.format(key))
        with self.forbid_concurrent_cache_access:
            self._load_tokens()
            if key in self.tokens:
                bearer, expiry = self.tokens[key]
                if is_expired(expiry):
                    logger.debug('Authentication token with "{0}" key is expired.'.format(key))
                    del self.tokens[key]
                else:
                    logger.debug('Using already received authentication, will expire on {0} (UTC).'.format(
                        datetime.datetime.utcfromtimestamp(expiry)))
                    return bearer

        logger.debug('Token cannot be found in cache.')
        if on_missing_token is not None:
            with self.forbid_concurrent_missing_token_function_call:
                state, token = on_missing_token(*on_missing_token_args)
                self.add_token(state, token)
                if key != state:
                    logger.warning('Using a token received on another key than expected. Expecting {0} but was {1}.'.format(key, state))
            with self.forbid_concurrent_cache_access:
                if state in self.tokens:
                    bearer, expiry = self.tokens[state]
                    logger.debug('Using newly received authentication, expiring on {0} (UTC).'.format(
                        datetime.datetime.utcfromtimestamp(expiry)))
                    return bearer

        logger.debug('User was not authenticated: key {0} cannot be found in {1}.'.format(key, self.tokens))
        raise AuthenticationFailed()

    def clear(self):
        with self.forbid_concurrent_cache_access:
            logger.debug('Clearing token cache.')
            self.tokens = {}
            self._clear()

    def _save_tokens(self):
        pass

    def _load_tokens(self):
        pass

    def _clear(self):
        pass


class JsonTokenFileCache(TokenMemoryCache):
    """
    Class to manage tokens using a cache file.
    """

    def __init__(self, tokens_path):
        TokenMemoryCache.__init__(self)
        self.tokens_path = tokens_path
        self.last_save_time = 0
        self._load_tokens()

    def _clear(self):
        self.last_save_time = 0
        try:
            os.remove(self.tokens_path)
        except:
            logger.debug('Cannot remove tokens file.')
            pass

    def _save_tokens(self):
        try:
            with open(self.tokens_path, 'w') as tokens_cache_file:
                json.dump(self.tokens, tokens_cache_file)
            self.last_save_time = os.path.getmtime(self.tokens_path)
        except Exception as e:
            logger.exception('Cannot save tokens.')

    def _load_tokens(self):
        if not os.path.exists(self.tokens_path):
            logger.debug('No token loaded. Token cache does not exists.')
            return
        try:
            last_modification_time = os.path.getmtime(self.tokens_path)
            if last_modification_time > self.last_save_time:
                self.last_save_time = last_modification_time
                with open(self.tokens_path, 'r') as tokens_cache_file:
                    self.tokens = json.load(tokens_cache_file)
        except Exception as e:
            logger.exception('Cannot load tokens.')
            pass
