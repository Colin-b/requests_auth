import unittest
import time
import requests
import multiprocessing
import logging
import datetime
import sys

logging.basicConfig(
    handlers=[logging.StreamHandler(sys.stdout)],
    level=logging.DEBUG,
    format='%(asctime)s [%(threadName)s] [%(levelname)s] %(message)s'
)

import authenticated_test_service

import requests_auth
import requests_auth.errors as errors


logger = logging.getLogger(__name__)


class JsonTokenFileCacheTest(unittest.TestCase):

    def setUp(self):
        self._token_cache = requests_auth.JsonTokenFileCache(self.id() + '.cache')

    def tearDown(self):
        self._token_cache.clear()

    def test_add_bearer_tokens(self):
        expiry_in_1_hour = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        token1 = authenticated_test_service.create_token(expiry_in_1_hour)
        self._token_cache.add_bearer_token('key1', token1)

        expiry_in_2_hour = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        token2 = authenticated_test_service.create_token(expiry_in_2_hour)
        self._token_cache.add_bearer_token('key2', token2)

        # Assert that tokens can be retrieved properly even after other token were inserted
        self.assertEqual(self._token_cache.get_token('key1'), token1)
        self.assertEqual(self._token_cache.get_token('key2'), token2)

        # Assert that tokens are not removed from the cache on retrieval
        self.assertEqual(self._token_cache.get_token('key1'), token1)
        self.assertEqual(self._token_cache.get_token('key2'), token2)

    def test_save_bearer_tokens(self):
        expiry_in_1_hour = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        token1 = authenticated_test_service.create_token(expiry_in_1_hour)
        self._token_cache.add_bearer_token('key1', token1)

        expiry_in_2_hour = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        token2 = authenticated_test_service.create_token(expiry_in_2_hour)
        self._token_cache.add_bearer_token('key2', token2)

        same_cache = requests_auth.JsonTokenFileCache(self.id() + '.cache')
        self.assertEqual(same_cache.get_token('key1'), token1)
        self.assertEqual(same_cache.get_token('key2'), token2)

    def test_missing_token(self):
        with self.assertRaises(errors.AuthenticationFailed):
            self._token_cache.get_token('key1')

    def test_missing_token_function(self):
        expiry_in_1_hour = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        token = authenticated_test_service.create_token(expiry_in_1_hour)
        retrieved_token = self._token_cache.get_token('key1', lambda: ('key1', token))
        self.assertEqual(retrieved_token, token)


class AzureADTest(unittest.TestCase):

    def test_corresponding_oauth2_implicit_flow_instance(self):
        aad = requests_auth.AzureActiveDirectoryImplicit(
            '45239d18-c68c-4c47-8bdd-ce71ea1d50cd',
            '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
        )
        self.assertRegex(aad.grant_details.url,
                         'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize?'
                         'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
                         '&response_type=token'
                         '&state=900fe3bb417d9c729361548bc6d3f83ad881e0b030ac27b2b563ee44ddf563c368612e8ee5b483f43667e897c96551388f6dfbdef83558ba2d6367d3b40d0496'
                         '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F'
                         '&nonce=%5B%27.*-.*-.*-.*-.*%27%5D'.replace('?', '\?'))
        self.assertRegex(str(aad),
                         "OAuth2Implicit("
                         "'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize', "
                         "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', "
                         "nonce='.*-.*-.*-.*-.*')".replace('(', '\(').replace(')', '\)'))

    def test_corresponding_oauth2_implicit_flow_instance_using_helper(self):
        aad = requests_auth.aad(
            requests_auth.OAuth2Flow.Implicit,
            '45239d18-c68c-4c47-8bdd-ce71ea1d50cd',
            '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
        )
        self.assertRegex(aad.grant_details.url,
                         'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize?'
                         'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
                         '&response_type=token'
                         '&state=900fe3bb417d9c729361548bc6d3f83ad881e0b030ac27b2b563ee44ddf563c368612e8ee5b483f43667e897c96551388f6dfbdef83558ba2d6367d3b40d0496'
                         '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F'
                         '&nonce=%5B%27.*-.*-.*-.*-.*%27%5D'.replace('?', '\?'))
        self.assertRegex(str(aad),
                         "OAuth2Implicit("
                         "'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize', "
                         "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', "
                         "nonce='.*-.*-.*-.*-.*')".replace('(', '\(').replace(')', '\)'))


    def test_corresponding_oauth2_implicit_flow_id_token_instance(self):
        aad = requests_auth.AzureActiveDirectoryImplicitIdToken(
            '45239d18-c68c-4c47-8bdd-ce71ea1d50cd',
            '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
        )
        self.assertRegex(aad.grant_details.url,
                         'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize?'
                         'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
                         '&response_type=id_token'
                         '&state=c141cf16f45343f37ca8053b6d0c67bad30a777b00221132d5a4514dd23082994e553a9f9fb45224ab9c2da3380047b32948fc2bf233efddc2fbd5801fc1d2d9'
                         '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F'
                         '&nonce=%5B%27.*-.*-.*-.*-.*%27%5D'.replace('?', '\?'))
        self.assertRegex(str(aad),
                         "OAuth2Implicit("
                         "'https://login.microsoftonline.com/45239d18-c68c-4c47-8bdd-ce71ea1d50cd/oauth2/authorize', "
                         "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', "
                         "response_type='id_token', "
                         "token_field_name='id_token', "
                         "nonce='.*-.*-.*-.*-.*')".replace('(', '\(').replace(')', '\)'))


class OktaTest(unittest.TestCase):

    def test_corresponding_oauth2_implicit_flow_instance(self):
        okta = requests_auth.OktaImplicit(
            'testserver.okta-emea.com',
            '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
        )
        self.assertRegex(okta.grant_details.url,
                         'https://testserver.okta-emea.com/oauth2/v1/authorize?'
                         'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
                         '&scope=openid+profile+email'
                         '&response_type=token'
                         '&state=f52217fda42a2089f9624cd7a36bb15bff1fb713144cbefbf3ace96c06b0adff46f854c803a41aa09b4b8a6fedf188f4d0ce3f84a6164a6a5db1cd7c004f9d91'
                         '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F'
                         '&nonce=%5B%27.*-.*-.*-.*-.*%27%5D'.replace('?', '\?').replace('+', '\+'))
        self.assertRegex(str(okta),
                         "OAuth2Implicit("
                         "'https://testserver.okta-emea.com/oauth2/v1/authorize', "
                         "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', "
                         "nonce='.*-.*-.*-.*-.*', "
                         "scope='openid profile email')".replace('(', '\(').replace(')', '\)'))

    def test_corresponding_oauth2_implicit_flow_instance_using_helper(self):
        okta = requests_auth.okta(
            requests_auth.OAuth2Flow.Implicit,
            'testserver.okta-emea.com',
            '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
        )
        self.assertRegex(okta.grant_details.url,
                         'https://testserver.okta-emea.com/oauth2/v1/authorize?'
                         'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
                         '&scope=openid+profile+email'
                         '&response_type=token'
                         '&state=f52217fda42a2089f9624cd7a36bb15bff1fb713144cbefbf3ace96c06b0adff46f854c803a41aa09b4b8a6fedf188f4d0ce3f84a6164a6a5db1cd7c004f9d91'
                         '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F'
                         '&nonce=%5B%27.*-.*-.*-.*-.*%27%5D'.replace('?', '\?').replace('+', '\+'))
        self.assertRegex(str(okta),
                         "OAuth2Implicit("
                         "'https://testserver.okta-emea.com/oauth2/v1/authorize', "
                         "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', "
                         "nonce='.*-.*-.*-.*-.*', "
                         "scope='openid profile email')".replace('(', '\(').replace(')', '\)'))

    def test_corresponding_oauth2_implicit_flow_id_token_instance(self):
        okta = requests_auth.OktaImplicitIdToken(
            'testserver.okta-emea.com',
            '54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
        )
        self.assertRegex(okta.grant_details.url,
                         'https://testserver.okta-emea.com/oauth2/v1/authorize?'
                         'client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd'
                         '&response_type=id_token'
                         '&scope=openid+profile+email'
                         '&state=da5a9f82a677a9b3bf19ce2f063f336f1968b8960d4626b35f7d4c0aee68e48ae1a5d5994dc78c3deb043d0e431c5be0bb084c8ac39bd41d670780306329d5a8'
                         '&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F'
                         '&nonce=%5B%27.*-.*-.*-.*-.*%27%5D'.replace('?', '\?').replace('+', '\+'))
        self.assertRegex(str(okta),
                         "OAuth2Implicit("
                         "'https://testserver.okta-emea.com/oauth2/v1/authorize', "
                         "client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', "
                         "response_type='id_token', "
                         "token_field_name='id_token', "
                         "nonce='.*-.*-.*-.*-.*', "
                         "scope='openid profile email')".replace('(', '\(').replace(')', '\)'))


TEST_SERVICE_PORT = 5001  # TODO Should use a method to retrieve a free port instead
TEST_SERVICE_HOST = 'http://localhost:{0}'.format(TEST_SERVICE_PORT)
TIMEOUT = 10


def call(auth):
    return requests.get(TEST_SERVICE_HOST + '/get_headers', auth=auth, timeout=TIMEOUT)


def get_header(auth):
    response = requests.get(TEST_SERVICE_HOST + '/get_headers', auth=auth, timeout=TIMEOUT)
    response.raise_for_status()
    return dict(response.json())


def get_query_args(auth):
    response = requests.get(TEST_SERVICE_HOST + '/get_query_args', auth=auth, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def can_connect_to_server():
    try:
        resp = requests.get('http://localhost:{0}/status'.format(TEST_SERVICE_PORT), timeout=0.5)
        return resp.status_code == 200
    except:
        return False


def _wait_for_server_to_be_started():
    for attempt in range(3):
        if can_connect_to_server():
            logger.info('Test server is started')
            break
        logger.info('Test server still not started...')
    else:
        raise Exception('Test server was not able to start.')


class AuthenticationTest(unittest.TestCase):
    test_service_process = multiprocessing.Process(
        target=authenticated_test_service.start_server, args=(TEST_SERVICE_PORT,)
    )

    @classmethod
    def setUpClass(cls):
        cls.test_service_process.start()
        _wait_for_server_to_be_started()

    @classmethod
    def tearDownClass(cls):
        cls.test_service_process.terminate()
        cls.test_service_process.join(timeout=0.5)

    def setUp(self):
        requests_auth.OAuth2.token_cache.clear()

    def test_oauth2_implicit_flow_url_is_mandatory(self):
        with self.assertRaises(Exception) as cm:
            requests_auth.OAuth2Implicit(None)
        self.assertEqual(str(cm.exception), 'Authorization URL is mandatory.')

    def test_oauth2_implicit_flow_token_is_not_reused_if_a_url_parameter_is_changing(self):
        auth1 = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_custom_token?response_type=custom_token&fake_param=1',
            timeout=TIMEOUT,
            token_field_name='custom_token'
        )
        token_on_auth1 = get_header(auth1).get('Authorization')
        self.assertRegex(token_on_auth1, '^Bearer .*')

        # Ensure that the new generated token will be different than previous one
        time.sleep(1)

        logger.info('Requesting a custom token with a different parameter in URL.')

        auth2 = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_custom_token?response_type=custom_token&fake_param=2',
            timeout=TIMEOUT,
            token_field_name='custom_token'
        )
        token_on_auth2 = get_header(auth2).get('Authorization')
        self.assertRegex(token_on_auth2, '^Bearer .*')

        self.assertNotEqual(token_on_auth1, token_on_auth2)

    def test_oauth2_implicit_flow_token_is_reused_if_only_nonce_differs(self):
        auth1 = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_custom_token?response_type=custom_token&nonce=1',
            timeout=TIMEOUT,
            token_field_name='custom_token'
        )
        token_on_auth1 = get_header(auth1).get('Authorization')
        self.assertRegex(token_on_auth1, '^Bearer .*')

        auth2 = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_custom_token?response_type=custom_token&nonce=2',
            timeout=TIMEOUT,
            token_field_name='custom_token'
        )
        token_on_auth2 = get_header(auth2).get('Authorization')
        self.assertRegex(token_on_auth2, '^Bearer .*')

        self.assertEqual(token_on_auth1, token_on_auth2)

    def test_oauth2_implicit_flow_token_can_be_requested_on_a_custom_server_port(self):
        auth = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_access_token',
            # TODO Should use a method to retrieve a free port instead
            redirect_uri_port=5002,
            timeout=TIMEOUT
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer .*')

    def test_oauth2_implicit_flow_post_token_is_sent_in_authorization_header_by_default(self):
        auth = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_access_token',
            timeout=TIMEOUT
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer .*')

    def test_oauth2_implicit_flow_get_token_is_sent_in_authorization_header_by_default(self):
        auth = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_anchor_access_token',
            timeout=TIMEOUT
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer .*')

    def test_oauth2_implicit_flow_token_is_sent_in_requested_field(self):
        auth = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_access_token',
            timeout=TIMEOUT,
            header_name='Bearer',
            header_value='{token}'
        )
        self.assertIsNotNone(get_header(auth).get('Bearer'))

    def test_oauth2_implicit_flow_can_send_a_custom_response_type_and_expects_token_to_be_received_with_this_name(self):
        auth = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_custom_token',
            timeout=TIMEOUT,
            response_type='custom_token',
            token_field_name='custom_token',
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer .*')

    def test_oauth2_implicit_flow_expects_token_in_id_token_if_response_type_is_id_token(self):
        auth = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_id_token',
            timeout=TIMEOUT,
            response_type='id_token',
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer .*')

    def test_oauth2_implicit_flow_expects_token_in_id_token_if_response_type_in_url_is_id_token(self):
        auth = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_id_token?response_type=id_token',
            timeout=TIMEOUT,
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer .*')

    def test_oauth2_implicit_flow_expects_token_to_be_stored_in_access_token_by_default(self):
        auth = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_access_token',
            timeout=TIMEOUT
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer .*')

    def test_oauth2_implicit_flow_token_is_reused_if_not_expired(self):
        auth1 = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_access_token',
            timeout=TIMEOUT
        )
        token1 = get_header(auth1).get('Authorization')
        self.assertRegex(token1, '^Bearer .*')

        oauth2 = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_token_as_access_token',
            timeout=TIMEOUT
        )
        token2 = get_header(oauth2).get('Authorization')
        self.assertRegex(token2, '^Bearer .*')

        # As the token should not be expired, this call should use the same token
        self.assertEqual(token1, token2)

    def test_oauth2_implicit_flow_post_failure_if_token_is_not_provided(self):
        with self.assertRaises(Exception) as cm:
            call(requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + '/do_not_provide_token',
                timeout=TIMEOUT)
            )
        self.assertEqual('access_token not provided within {}.', str(cm.exception))

    def test_oauth2_implicit_flow_get_failure_if_token_is_not_provided(self):
        with self.assertRaises(Exception) as cm:
            call(requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + '/do_not_provide_token_as_anchor_token',
                timeout=TIMEOUT
            ))
        self.assertEqual("access_token not provided within {}.", str(cm.exception))

    def test_oauth2_implicit_flow_post_failure_if_state_is_not_provided(self):
        with self.assertRaises(Exception) as cm:
            call(requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + '/provide_token_as_access_token_but_without_providing_state',
                timeout=TIMEOUT
            ),)
        self.assertRegex(str(cm.exception), "state not provided within {'access_token': \['.*'\]}.")

    def test_oauth2_implicit_flow_get_failure_if_state_is_not_provided(self):
        with self.assertRaises(Exception) as cm:
            call(requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + '/provide_token_as_anchor_access_token_but_without_providing_state',
                timeout=TIMEOUT
            ),)
        self.assertRegex(str(cm.exception), "state not provided within {'access_token': \['.*'\]}.")

    def test_oauth2_implicit_flow_failure_if_token_is_not_received_within_the_timeout_interval(self):
        with self.assertRaises(Exception) as cm:
            call(requests_auth.OAuth2Implicit(
                TEST_SERVICE_HOST + '/do_not_redirect',
                timeout=TIMEOUT
            ))
        self.assertEqual('User authentication was not received within {timeout} seconds.'.
                         format(timeout=TIMEOUT), str(cm.exception))

    def test_oauth2_implicit_flow_token_is_requested_again_if_expired(self):
        # This token will expires in 1 seconds
        auth1 = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_a_token_expiring_in_1_second',
            timeout=TIMEOUT
        )
        token1 = get_header(auth1).get('Authorization')
        self.assertRegex(token1, '^Bearer .*')

        # Wait for 2 seconds to ensure that the token expiring in 1 seconds will be considered as expired
        time.sleep(2)

        # Token should now be expired, a new one should be requested
        auth2 = requests_auth.OAuth2Implicit(
            TEST_SERVICE_HOST + '/provide_a_token_expiring_in_1_second',
            timeout=TIMEOUT
        )
        token2 = get_header(auth2).get('Authorization')
        self.assertRegex(token2, '^Bearer .*')

        self.assertNotEqual(token1, token2)

    def test_oauth2_authorization_code_flow_get_code_is_sent_in_authorization_header_by_default(self):
        auth = requests_auth.OAuth2AuthorizationCode(
            TEST_SERVICE_HOST + '/provide_code_as_anchor_code',
            TEST_SERVICE_HOST + '/provide_access_token',
            timeout=TIMEOUT
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer 2YotnFZFEjr1zCsicMWpAA')

    def test_oauth2_password_credentials_flow_token_is_sent_in_authorization_header_by_default(self):
        auth = requests_auth.OAuth2ResourceOwnerPasswordCredentials(
            TEST_SERVICE_HOST + '/provide_access_token',
            username='test_user',
            password='test_pwd',
            timeout=TIMEOUT
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer 2YotnFZFEjr1zCsicMWpAA')

    def test_oauth2_client_credentials_flow_token_is_sent_in_authorization_header_by_default(self):
        auth = requests_auth.OAuth2ClientCredentials(
            TEST_SERVICE_HOST + '/provide_access_token',
            username='test_user',
            password='test_pwd',
            timeout=TIMEOUT
        )
        self.assertRegex(get_header(auth).get('Authorization'), '^Bearer 2YotnFZFEjr1zCsicMWpAA')

    def test_header_api_key_requires_an_api_key(self):
        with self.assertRaises(Exception) as cm:
            requests_auth.HeaderApiKey(None)
        self.assertEqual('API Key is mandatory.', str(cm.exception))

    def test_query_api_key_requires_an_api_key(self):
        with self.assertRaises(Exception) as cm:
            requests_auth.QueryApiKey(None)
        self.assertEqual('API Key is mandatory.', str(cm.exception))

    def test_header_api_key_is_sent_in_X_Api_Key_by_default(self):
        auth = requests_auth.HeaderApiKey('my_provided_api_key')
        self.assertEqual(get_header(auth).get('X-Api-Key'), 'my_provided_api_key')

    def test_query_api_key_is_sent_in_api_key_by_default(self):
        auth = requests_auth.QueryApiKey('my_provided_api_key')
        self.assertEqual(get_query_args(auth).get('api_key'), 'my_provided_api_key')

    def test_header_api_key_can_be_sent_in_a_custom_field_name(self):
        auth = requests_auth.HeaderApiKey('my_provided_api_key', 'X-API-HEADER-KEY')
        self.assertEqual(get_header(auth).get('X-Api-Header-Key'), 'my_provided_api_key')

    def test_query_api_key_can_be_sent_in_a_custom_field_name(self):
        auth = requests_auth.QueryApiKey('my_provided_api_key', 'X-API-QUERY-KEY')
        self.assertEqual(get_query_args(auth).get('X-API-QUERY-KEY'), 'my_provided_api_key')

    def test_basic_authentication_send_authorization_header(self):
        auth = requests_auth.Basic('test_user', 'test_pwd')
        self.assertEqual(get_header(auth).get('Authorization'), 'Basic dGVzdF91c2VyOnRlc3RfcHdk')

    def test_basic_and_api_key_authentication_can_be_combined(self):
        basic_auth = requests_auth.Basic('test_user', 'test_pwd')
        api_key_auth = requests_auth.HeaderApiKey('my_provided_api_key')
        header = get_header(basic_auth + api_key_auth)
        self.assertEqual(header.get('Authorization'), 'Basic dGVzdF91c2VyOnRlc3RfcHdk')
        self.assertEqual(header.get('X-Api-Key'), 'my_provided_api_key')

    def test_basic_and_api_key_authentication_can_be_combined_deprecated(self):
        basic_auth = requests_auth.Basic('test_user', 'test_pwd')
        api_key_auth = requests_auth.HeaderApiKey('my_provided_api_key')
        header = get_header(requests_auth.Auths(basic_auth, api_key_auth))
        self.assertEqual(header.get('Authorization'), 'Basic dGVzdF91c2VyOnRlc3RfcHdk')
        self.assertEqual(header.get('X-Api-Key'), 'my_provided_api_key')


if __name__ == '__main__':
    unittest.main(buffer=False)
