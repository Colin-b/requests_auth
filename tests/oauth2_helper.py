import multiprocessing
import logging
import urllib.request
import threading

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
            f"http://localhost:{port}/status", timeout=0.5
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


@pytest.fixture
def browser_mock(monkeypatch):
    mock = BrowserMock()
    import requests_auth.oauth2_authentication_responses_server

    monkeypatch.setattr(
        requests_auth.oauth2_authentication_responses_server.webbrowser,
        "get",
        lambda *args: mock,
    )
    yield mock
    mock.assert_checked()


def send_reply(reply_url, data):
    response = urllib.request.urlopen(reply_url, data=data)
    # Simulate requests_auth JS to retrieve fragment
    if (
        response.read()
        == b'<html><body><script>\n        var new_url = window.location.href.replace("#","?");\n        if (new_url.indexOf("?") !== -1) {\n            new_url += "&requests_auth_redirect=1";\n        } else {\n            new_url += "?requests_auth_redirect=1";\n        }\n        window.location.replace(new_url)\n        </script></body></html>'
    ):
        reply_url = reply_url.replace("#", "?")
        reply_url += (
            "&requests_auth_redirect=1"
            if "?" in reply_url
            else "?requests_auth_redirect=1"
        )
        urllib.request.urlopen(reply_url, data=data)


class BrowserMock:
    def __init__(self):
        self.responses = {}
        self.without_responses = []

    def open(self, url: str, new: int):
        assert new == 1
        response = self.responses.pop(url, None)
        if response:
            # Simulate a browser by sending the response in another thread after a certain delay
            threading.Thread(target=send_reply, args=response).start()
        else:
            self.without_responses.append(url)
        return True

    def assert_called(self, url: str):
        self.without_responses.remove(url)

    def add_response(self, opened_url: str, reply_url: str, data: str = None):
        if data:
            data = data.encode()
        self.responses[opened_url] = reply_url, data

    def assert_checked(self):
        assert not self.responses
        assert not self.without_responses
