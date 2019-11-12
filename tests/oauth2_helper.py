import multiprocessing
import logging
import urllib.request

import pytest

from tests import authenticated_test_service
import requests_auth

logger = logging.getLogger(__name__)


TEST_SERVICE_PORT = 5001  # TODO Should use a method to retrieve a free port instead
TEST_SERVICE_HOST = "http://localhost:{0}".format(TEST_SERVICE_PORT)
TIMEOUT = 10


def can_connect_to_server(port: int):
    try:
        response = urllib.request.urlopen(
            "http://localhost:{0}/status".format(port), timeout=0.5
        )
        return response.code == 200
    except:
        return False


def _wait_for_server_to_be_started(port: int):
    for attempt in range(10):
        if can_connect_to_server(port):
            logger.info("Test server is started")
            break
        logger.info("Test server still not started...")
    else:
        raise Exception("Test server was not able to start.")


@pytest.fixture(scope="module")
def authenticated_service():
    test_service_process = multiprocessing.Process(
        target=authenticated_test_service.start_server, args=(TEST_SERVICE_PORT,)
    )
    test_service_process.start()
    _wait_for_server_to_be_started(TEST_SERVICE_PORT)
    yield test_service_process
    test_service_process.terminate()
    test_service_process.join(timeout=0.5)


@pytest.fixture
def token_cache():
    yield requests_auth.OAuth2.token_cache
    requests_auth.OAuth2.token_cache.clear()
