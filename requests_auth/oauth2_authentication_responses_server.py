import webbrowser
import logging
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
try:
    # Python 3
    from urllib.parse import parse_qs, urlparse
except ImportError:
    # Python 2
    from urlparse import parse_qs, urlparse

from requests_auth.errors import *

logger = logging.getLogger(__name__)


class OAuth2ResponseHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        # Do not consider a favicon request as an error
        if self.path == '/favicon.ico':
            logger.debug('Favicon request received on OAuth2 authentication response server.')
            return self.send_html('Favicon is not provided.')

        logger.debug('GET received on {0}'.format(self.path))
        try:
            args = self._get_params()
            if self.server.grant_details.name in args or args.pop('requests_auth_redirect', None):
                self._parse_grant(args)
            else:
                logger.debug('Send anchor grant as query parameter.')
                self.send_html(self.fragment_redirect_page())
        except Exception as e:
            self.server.request_error = e
            logger.exception("Unable to properly perform authentication.")
            self.send_html(self.error_page("Unable to properly perform authentication: {0}".format(e)))

    def do_POST(self):
        logger.debug('POST received on {0}'.format(self.path))
        try:
            form_dict = self._get_form()
            self._parse_grant(form_dict)
        except Exception as e:
            self.server.request_error = e
            logger.exception("Unable to properly perform authentication.")
            self.send_html(self.error_page("Unable to properly perform authentication: {0}".format(e)))

    def _parse_grant(self, arguments):
        grants = arguments.get(self.server.grant_details.name)
        if not grants or len(grants) > 1:
            raise GrantNotProvided(self.server.grant_details.name, arguments)
        logger.debug('Received grants: {0}'.format(grants))
        grant = grants[0]

        states = arguments.get('state')
        if not states or len(states) > 1:
            raise StateNotProvided(arguments)
        logger.debug('Received states: {0}'.format(states))
        state = states[0]
        self.server.grant = state, grant
        self.send_html(self.success_page("You are now authenticated on {0}. You may close this tab.".format(state)))

    def _get_form(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body_str = self.rfile.read(content_length).decode('utf-8')
        return parse_qs(body_str, keep_blank_values=1)

    def _get_params(self):
        return parse_qs(urlparse(self.path).query)

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
        </body>""".format(self.server.grant_details.reception_success_display_time, text)

    def error_page(self, text):
        return """<body onload="window.open('', '_self', ''); window.setTimeout(close, {0})" style="
        color: #D8000C;
        background-color: #FFBABA;
        font-size: xx-large;
        display: flex;
        align-items: center;
        justify-content: center;">
            <div style="border: 1px solid;">{1}</div>
        </body>""".format(self.server.grant_details.reception_failure_display_time, text)

    def fragment_redirect_page(self):
        """Return a page with JS that calls back the server on the url
        original url: scheme://FQDN/path#fragment
        call back url: scheme://FQDN/path?fragment

        The fragment part is used in the protocol for the client to retrieve the token.
        As the fragment part is not sent to the server (to avoid normally to see the token in the logs)
        we must call again the localhost server with the fragment transformed as query string.
        """
        return """<html><body><script>
        var new_url = window.location.href.replace("#","?");
        if (new_url.indexOf("?") !== -1) {
            new_url += "&requests_auth_redirect=1";
        } else {
            new_url += "?requests_auth_redirect=1";
        }
        window.location.replace(new_url)
        </script></body></html>"""

    def log_message(self, format, *args):
        """Make sure that messages are logged even with pythonw (seems like a bug in BaseHTTPRequestHandler)."""
        logger.info(format, *args)


class FixedHttpServer(HTTPServer):

    def __init__(self, grant_details):
        """

        :param grant_details: Must be a class providing the following attributes:
            * name
            * reception_success_display_time
            * reception_failure_display_time
            * redirect_uri_port
            * reception_timeout
        """
        HTTPServer.__init__(self, ('', grant_details.redirect_uri_port), OAuth2ResponseHandler)
        self.timeout = grant_details.reception_timeout
        logger.debug('Timeout is set to {0} seconds.'.format(self.timeout))
        self.grant_details = grant_details
        self.request_error = None
        self.grant = False

    def finish_request(self, request, client_address):
        """Make sure that timeout is used by the request (seems like a bug in HTTPServer)."""
        request.settimeout(self.timeout)
        HTTPServer.finish_request(self, request, client_address)

    def ensure_no_error_occurred(self):
        if self.request_error:  # Raise error encountered while processing a request if any
            raise self.request_error
        return not self.grant

    def handle_timeout(self):
        raise TimeoutOccurred(self.timeout)

    def __enter__(self):
        """Support for context manager use with Python < 3.6"""
        return self

    def __exit__(self, *args):
        """Support for context manager use with Python < 3.6"""
        self.server_close()


class GrantDetails:
    def __init__(self,
                 url,
                 name,
                 reception_timeout,
                 reception_success_display_time,
                 reception_failure_display_time,
                 redirect_uri_port):
        self.url = url
        self.name = name
        self.reception_timeout = reception_timeout
        self.reception_success_display_time = reception_success_display_time
        self.reception_failure_display_time = reception_failure_display_time
        self.redirect_uri_port = redirect_uri_port


def request_new_grant(grant_details):
    """
    Ask for a new OAuth2 grant.
    :param grant_details: Must be a class providing the following attributes:
        * url
        * name
        * reception_timeout
        * reception_success_display_time
        * reception_failure_display_time
        * redirect_uri_port
    :return:A tuple (state, grant) or an Exception if not retrieved within timeout.
    """
    logger.debug('Requesting new {0}...'.format(grant_details.name))

    with FixedHttpServer(grant_details) as server:
        _open_url(grant_details.url)
        return _wait_for_grant(server)


def _open_url(url):
    # Default to Microsoft Internet Explorer to be able to open a new window
    # otherwise this parameter is not taken into account by most browsers
    # Opening a new window allows to focus back once authenticated (JavaScript is closing the only tab)
    try:
        browser = webbrowser.get(webbrowser.iexplore) if hasattr(webbrowser, 'iexplore') else webbrowser.get()
        logger.info('Opening browser on {0}'.format(url))
        if not browser.open(url, new=1):
            logger.warning('Unable to open URL, try with a GET request.')
            requests.get(url)
    except webbrowser.Error:
        logger.exception('Unable to open URL, try with a GET request.')
        requests.get(url)


def _wait_for_grant(server):
    logger.debug('Waiting for user authentication...')
    while not server.grant:
        server.handle_request()
        server.ensure_no_error_occurred()
    return server.grant
