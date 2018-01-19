import webbrowser
import logging
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from requests_auth.errors import *

DEFAULT_SERVER_PORT = 5000
DEFAULT_PORT_AVAILABILITY_TIMEOUT = 2  # Time is expressed in seconds
DEFAULT_AUTHENTICATION_TIMEOUT = 60  # Time is expressed in seconds
DEFAULT_SUCCESS_DISPLAY_TIME = 1  # Time is expressed in milliseconds
DEFAULT_FAILURE_DISPLAY_TIME = 5000  # Time is expressed in milliseconds
DEFAULT_TOKEN_NAME = 'token'  # As described in https://tools.ietf.org/html/rfc6749#section-4.2.1

logger = logging.getLogger(__name__)


class OAuth2ResponseHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        # Do not consider a favicon request as an error
        if self.path == '/favicon.ico':
            logger.debug('Favicon request received on OAuth2 authentication response server.')
            return self.send_html('Favicon is not provided.')
        try:
            logger.exception("Unable to properly perform authentication. GET is not supported for now.")
            self.send_html(self.error_page("Unable to properly perform authentication. GET is not supported for now."))
        except Exception as e:
            self.server.request_error = e
            logger.exception("Unable to properly perform authentication.")
            self.send_html(self.error_page("Unable to properly perform authentication: {0}".format(e)))

    def do_POST(self):
        logger.debug('POST received on {0}'.format(self.path))
        try:
            form_dict = self._get_form()

            id_tokens = form_dict.get(self.server.oauth2.token_name)
            if not id_tokens or len(id_tokens) > 1:
                raise TokenNotProvided(self.server.oauth2.token_name, form_dict)
            logger.debug('Received tokens: {0}'.format(id_tokens))
            id_token = id_tokens[0]

            unique_token_provider_identifiers = form_dict.get('state')
            if not unique_token_provider_identifiers or len(unique_token_provider_identifiers) > 1:
                raise StateNotProvided(form_dict)
            logger.debug('Received states: {0}'.format(unique_token_provider_identifiers))
            unique_token_provider_identifier = unique_token_provider_identifiers[0]
            self.server.token = unique_token_provider_identifier, id_token
            self.send_html(self.success_page("You are now authenticated on {0}. You may close this tab.".format(
                unique_token_provider_identifier)))
        except Exception as e:
            self.server.request_error = e
            logger.exception("Unable to properly perform authentication.")
            self.send_html(self.error_page("Unable to properly perform authentication: {0}".format(e)))

    def _get_form(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body_str = self.rfile.read(content_length).decode('utf-8')
        return parse_qs(body_str, keep_blank_values=1)

    def send_html(self, html_content):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(str.encode(html_content))
        logger.debug('HTML content sent to client.')

    def success_page(self, text):
        return """<body onload="window.open('', '_self', ''); window.setTimeout(close, {0})" style="
        color: #4F8A10;
        background-color: #DFF2BF;
        font-size: xx-large;
        display: flex;
        align-items: center;
        justify-content: center;">
            <div style="border: 1px solid;">{1}</div>
        </body>""".format(self.server.oauth2.token_reception_success_display_time, text)

    def error_page(self, text):
        return """<body onload="window.open('', '_self', ''); window.setTimeout(close, {0})" style="
        color: #D8000C;
        background-color: #FFBABA;
        font-size: xx-large;
        display: flex;
        align-items: center;
        justify-content: center;">
            <div style="border: 1px solid;">{1}</div>
        </body>""".format(self.server.oauth2.token_reception_failure_display_time, text)

    def log_message(self, format, *args):
        """Make sure that messages are logged even with pythonw (seems like a bug in BaseHTTPRequestHandler)."""
        logger.info(format, *args)


class FixedHttpServer(HTTPServer):

    def __init__(self, oauth2):
        HTTPServer.__init__(self, ('', oauth2.redirect_uri_port), OAuth2ResponseHandler)
        self.timeout = oauth2.token_reception_timeout
        logger.debug('Timeout is set to {0} seconds.'.format(self.timeout))
        self.oauth2 = oauth2
        self.request_error = None
        self.token = False

    def finish_request(self, request, client_address):
        """Make sure that timeout is used by the request (seems like a bug in HTTPServer)."""
        request.settimeout(self.timeout)
        HTTPServer.finish_request(self, request, client_address)

    def ensure_no_error_occurred(self):
        if self.request_error:  # Raise error encountered while processing a request if any
            raise self.request_error
        return not self.token

    def handle_timeout(self):
        raise TimeoutOccurred(self.timeout)

    def __enter__(self):
        """Support for context manager use with Python < 3.6"""
        return self

    def __exit__(self, *args):
        """Support for context manager use with Python < 3.6"""
        self.server_close()


def request_new_token(oauth2):
    """
    Ask for a new OAuth2 Bearer token.
    :param oauth2: authentication.OAuth2Auth instance
    :return: The token or an Exception if not retrieved.
    """
    logger.debug('Requesting user authentication...')

    with FixedHttpServer(oauth2) as server:
        _open_url(oauth2.full_url)
        return _wait_for_token(server)


def _open_url(url):
    # Default to Microsoft Internet Explorer to be able to open a new window
    # otherwise this parameter is not taken into account by most browsers
    # Opening a new window allows to focus back once authenticated (JavaScript is closing the only tab)
    try:
        browser = webbrowser.get(webbrowser.iexplore) if hasattr(webbrowser, 'iexplore') else webbrowser.get()
        logger.info('Opening browser on {0}'.format(url))
        if not browser.open(url, 1):
            logger.warning('Unable to open URL, try with a GET request.')
            requests.get(url)
    except webbrowser.Error:
        logger.exception('Unable to open URL, try with a GET request.')
        requests.get(url)


def _wait_for_token(server):
    logger.debug('Waiting for user authentication...')
    while not server.token:
        server.handle_request()
        server.ensure_no_error_occurred()
    return server.token
