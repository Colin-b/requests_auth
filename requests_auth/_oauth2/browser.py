class BrowserAuth:
    def __init__(self, kwargs):
        """
        :param redirect_uri_domain: FQDN to use in the redirect_uri when localhost (default) is not allowed.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 code will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a code or a token to be received once requested.
        Wait for 1 minute (60 seconds) by default.
        :param success_display_time: In case a code is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received code is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        """
        redirect_uri_domain = kwargs.pop("redirect_uri_domain", None) or "localhost"
        redirect_uri_endpoint = kwargs.pop("redirect_uri_endpoint", None) or ""
        self.redirect_uri_port = int(kwargs.pop("redirect_uri_port", None) or 5000)
        self.redirect_uri = f"http://{redirect_uri_domain}:{self.redirect_uri_port}/{redirect_uri_endpoint}"

        # Time is expressed in seconds
        self.timeout = float(kwargs.pop("timeout", None) or 60)
        # Time is expressed in milliseconds
        self.success_display_time = int(kwargs.pop("success_display_time", None) or 1)
        # Time is expressed in milliseconds
        self.failure_display_time = int(
            kwargs.pop("failure_display_time", None) or 5000
        )
