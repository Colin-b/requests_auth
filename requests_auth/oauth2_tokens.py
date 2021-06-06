import base64
import json
import os
import datetime
import threading
import logging
from requests_auth.errors import *

logger = logging.getLogger(__name__)


def decode_base64(base64_encoded_string: str) -> str:
    """
    Decode base64, padding being optional.

    :param base64_encoded_string: Base64 data as an ASCII byte string
    :returns: The decoded byte string.
    """
    missing_padding = len(base64_encoded_string) % 4
    if missing_padding != 0:
        base64_encoded_string += "=" * (4 - missing_padding)
    return base64.b64decode(base64_encoded_string).decode("unicode_escape")


def is_expired(expiry: float) -> bool:
    return datetime.datetime.utcfromtimestamp(expiry) < datetime.datetime.utcnow()


class TokenMemoryCache:
    """
    Class to manage tokens using memory storage.
    """

    def __init__(self):
        self.tokens = {}
        self.forbid_concurrent_cache_access = threading.Lock()
        self.forbid_concurrent_missing_token_function_call = threading.Lock()

    def add_bearer_token(self, key: str, token: str):
        """
        Set the bearer token and save it
        :param key: key identifier of the token
        :param token: value
        :raise InvalidToken: In case token is invalid.
        :raise TokenExpiryNotProvided: In case expiry is not provided.
        """
        if not token:
            raise InvalidToken(token)

        header, body, other = token.split(".")
        body = json.loads(decode_base64(body))
        expiry = body.get("exp")
        if not expiry:
            raise TokenExpiryNotProvided(expiry)

        self._add_token(key, token, expiry)

    def add_access_token(self, key: str, token: str, expires_in: int, refresh_token: str = None):
        """
        Set the bearer token and save it
        :param key: key identifier of the token
        :param token: value
        :param expires_in: Number of seconds before token expiry
        :param refresh_token: refresh token value
        :raise InvalidToken: In case token is invalid.
        """
        expiry = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc
        ) + datetime.timedelta(seconds=int(expires_in))
        self._add_token(key, token, expiry.timestamp(), refresh_token)

    def _add_token(self, key: str, token: str, expiry: float, refresh_token: str = None):
        """
        Set the bearer token and save it
        :param key: key identifier of the token
        :param token: value
        :param expiry: UTC timestamp of expiry
        :param refresh_token: refresh token value
        """
        with self.forbid_concurrent_cache_access:
            self.tokens[key] = token, expiry, refresh_token
            self._save_tokens()
            logger.debug(
                f'Inserting token expiring on {datetime.datetime.utcfromtimestamp(expiry)} (UTC) with "{key}" key: {token}'
            )

    def get_token(self, key: str, on_missing_token=None, *on_missing_token_args, on_expired_token=None) -> str:
        """
        Return the bearer token.
        :param key: key identifier of the token
        :param on_missing_token: function to call when token is expired or missing (returning token and expiry tuple)
        :param on_missing_token_args: arguments of the function
        :param on_expired_token: function to call to refresh the token when it is expired
        :return: the token
        :raise AuthenticationFailed: in case token cannot be retrieved.
        """
        logger.debug(f'Retrieving token with "{key}" key.')
        refresh_token = None
        with self.forbid_concurrent_cache_access:
            self._load_tokens()
            if key in self.tokens:
                token = self.tokens[key]
                if len(token) == 2:  # No refresh token
                    bearer, expiry = token
                else:
                    bearer, expiry, refresh_token = token
                if is_expired(expiry):
                    logger.debug(f'Authentication token with "{key}" key is expired.')
                    del self.tokens[key]
                else:
                    logger.debug(
                        f"Using already received authentication, will expire on {datetime.datetime.utcfromtimestamp(expiry)} (UTC)."
                    )
                    return bearer

        if refresh_token is not None and on_expired_token is not None:
            try:
                with self.forbid_concurrent_missing_token_function_call:
                    state, token, expires_in, refresh_token = on_expired_token(refresh_token)
                    self.add_access_token(state, token, expires_in, refresh_token)
                    logger.debug(f"Refreshed token with key {key}.")
                with self.forbid_concurrent_cache_access:
                    if state in self.tokens:
                        bearer, expiry, refresh_token = self.tokens[state]
                        logger.debug(f"Using newly refreshed token, expiring on {datetime.datetime.utcfromtimestamp(expiry)} (UTC).")
                        return bearer
            except (InvalidGrantRequest, GrantNotProvided):
                logger.debug(f"Failed to refresh token.")

        logger.debug("Token cannot be found in cache.")
        if on_missing_token is not None:
            with self.forbid_concurrent_missing_token_function_call:
                new_token = on_missing_token(*on_missing_token_args)
                if len(new_token) == 2:  # Bearer token
                    state, token = new_token
                    self.add_bearer_token(state, token)
                elif len(new_token) == 3:  # Access token
                    state, token, expires_in = new_token
                    self.add_access_token(state, token, expires_in)
                else:  # Access token and Refresh token
                    state, token, expires_in, refresh_token = new_token
                    self.add_access_token(state, token, expires_in, refresh_token)
                if key != state:
                    logger.warning(
                        f"Using a token received on another key than expected. Expecting {key} but was {state}."
                    )
            with self.forbid_concurrent_cache_access:
                if state in self.tokens:
                    bearer, expiry, refresh_token = self.tokens[state]
                    logger.debug(
                        f"Using newly received authentication, expiring on {datetime.datetime.utcfromtimestamp(expiry)} (UTC)."
                    )
                    return bearer

        logger.debug(
            f"User was not authenticated: key {key} cannot be found in {self.tokens}."
        )
        raise AuthenticationFailed()

    def clear(self):
        with self.forbid_concurrent_cache_access:
            logger.debug("Clearing token cache.")
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

    def __init__(self, tokens_path: str):
        TokenMemoryCache.__init__(self)
        self.tokens_path = tokens_path
        self.last_save_time = 0
        self._load_tokens()

    def _clear(self):
        self.last_save_time = 0
        try:
            os.remove(self.tokens_path)
        except:
            logger.debug("Cannot remove tokens file.")

    def _save_tokens(self):
        try:
            with open(self.tokens_path, "w") as tokens_cache_file:
                json.dump(self.tokens, tokens_cache_file)
            self.last_save_time = os.path.getmtime(self.tokens_path)
        except:
            logger.exception("Cannot save tokens.")

    def _load_tokens(self):
        if not os.path.exists(self.tokens_path):
            logger.debug("No token loaded. Token cache does not exists.")
            return
        try:
            last_modification_time = os.path.getmtime(self.tokens_path)
            if last_modification_time > self.last_save_time:
                self.last_save_time = last_modification_time
                with open(self.tokens_path, "r") as tokens_cache_file:
                    self.tokens = json.load(tokens_cache_file)
        except:
            logger.exception("Cannot load tokens.")
