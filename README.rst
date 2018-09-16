Easy Authentication for Requests
================================

This module provides you authentication classes to be used with `requests module`_.

To use a specific authentication in combination with requests, use the `authentication parameter on requests module`_.

OAuth 2
=======

Sample:

.. code:: python

    import requests
    from requests_auth import OAuth2

    requests.get('http://www.example.com', auth=OAuth2('https://www.example.com'))

Parameters
----------

+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
|                                        | Description                                                                                                                              | Mandatory | Default value  |
+========================================+==========================================================================================================================================+===========+================+
| authorization_url                      | OAuth 2 authorization URL.                                                                                                               | Mandatory |                |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| redirect_uri_endpoint                  | Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>.       | Optional  | ''             |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| redirect_uri_port                      | The port on which the server listening for the OAuth 2 token will be started.                                                            | Optional  | 5000           |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| redirect_uri_port_availability_timeout | The maximum amount of seconds to wait for the redirect_uri_port to become available.                                                     | Optional  | 2              |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| token_reception_timeout                | Maximum amount of seconds to wait for a token to be received once requested.                                                             | Optional  | 60             |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| token_reception_success_display_time   | In case a token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser. | Optional  | 1              |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| token_reception_failure_display_time   | In case received token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser.      | Optional  | 5000           |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| header_name                            | Name of the header field used to send token.                                                                                             | Optional  | Authorization  |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| header_value                           | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token.                               | Optional  | Bearer {token} |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| any other parameter                    | all additional authorization parameters that should be put as query parameter in the authorization URL.                                  | Optional  |                |
|                                        | * client_id: Corresponding to your Application ID (in Microsoft Azure app portal)                                                        |           |                |
|                                        | * response_type: id_token for Microsoft                                                                                                  |           |                |
|                                        | * nonce: Refer to `OpenID ID Token specifications`_ for more details                                                                     |           |                |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+

Managing token cache
--------------------

To avoid asking for a new token every new request, a token cache is used.

Default cache is in memory but it is also possible to use a physical cache using the following method:

.. code:: python

    from requests_auth import OAuth2, JsonTokenFileCache

    OAuth2.token_cache = JsonTokenFileCache('my_token_cache')

Common OAuth2 providers
-----------------------

Microsoft
---------

Sample:

.. code:: python

    import requests
    from requests_auth import MSOAuth2


    ms_auth = MSOAuth2(tenant_id='45239d18-c68c-4c47-8bdd-ce71ea1d50cd', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', nonce='7362CAEA-9CA5-4B43-9BA3-34D7C303EBA7')
    requests.get('http://www.example.com', auth=ms_auth)

Parameters
----------

+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
|                                        | Description                                                                                                                              | Mandatory | Default value |
+========================================+==========================================================================================================================================+===========+================+
| tenant_id                              | Microsoft Tenant Identifier (formatted as 45239d18-c68c-4c47-8bdd-ce71ea1d50cd).                                                         | Mandatory |                |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| client_id                              | Microsoft Application Identifier (formatted as 45239d18-c68c-4c47-8bdd-ce71ea1d50cd).                                                    | Mandatory |                |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| nonce                                  | Refer to `OpenID ID Token specifications`_ for more details (formatted as 7362CAEA-9CA5-4B43-9BA3-34D7C303EBA7)                          | Mandatory |                |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| redirect_uri_endpoint                  | Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>.       | Optional  | ''             |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| redirect_uri_port                      | The port on which the server listening for the OAuth 2 token will be started.                                                            | Optional  | 5000           |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| redirect_uri_port_availability_timeout | The maximum amount of seconds to wait for the redirect_uri_port to become available.                                                     | Optional  | 2              |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| token_reception_timeout                | Maximum amount of seconds to wait for a token to be received once requested.                                                             | Optional  | 60             |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| token_reception_success_display_time   | In case a token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser. | Optional  | 1              |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| token_reception_failure_display_time   | In case received token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser.      | Optional  | 5000           |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| header_name                            | Name of the header field used to send token.                                                                                             | Optional  | Authorization  |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| header_value                           | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token.                               | Optional  | Bearer {token} |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+
| any other parameter                    | all additional authorization parameters that should be put as query parameter in the authorization URL.                                  | Optional  |                |
+----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------+-----------+----------------+

API key in header
=================

Sample:

.. code:: python

    import requests
    from requests_auth import HeaderApiKey

    requests.get('http://www.example.com', auth=HeaderApiKey('my_api_key'))

Parameters
----------

+-------------+--------------------------------+-----------+---------------+
|             | Description                    | Mandatory | Default value |
+=============+================================+===========+===============+
| api_key     | The API key that will be sent. | Mandatory |               |
+-------------+--------------------------------+-----------+---------------+
| header_name | Name of the header field.      | Optional  | "X-API-Key"   |
+-------------+--------------------------------+-----------+---------------+

API key in query
================

Sample:

.. code:: python

    import requests
    from requests_auth import QueryApiKey

    requests.get('http://www.example.com', auth=QueryApiKey('my_api_key'))

Parameters
----------

+----------------------+--------------------------------+-----------+---------------+
|                      | Description                    | Mandatory | Default value |
+======================+================================+===========+===============+
| api_key              | The API key that will be sent. | Mandatory |               |
+----------------------+--------------------------------+-----------+---------------+
| query_parameter_name | Name of the query parameter.   | Optional  | "api_key"     |
+----------------------+--------------------------------+-----------+---------------+

Basic
=====

Sample:

.. code:: python

    import requests
    from requests_auth import Basic

    requests.get('http://www.example.com', auth=Basic('username', 'password'))

Parameters
----------

+----------+----------------+-----------+
|          | Description    | Mandatory |
+==========+================+===========+
| username | User name.     | Mandatory |
+----------+----------------+-----------+
| password | User password. | Mandatory |
+----------+----------------+-----------+

NTLM
====

Requires `requests-negotiate-sspi module`_ or `requests_ntlm module`_ depending on provided parameters.

Sample:

.. code:: python

    import requests
    from requests_auth import NTLM

    requests.get('http://www.example.com', auth=NTLM())

Parameters
----------

+----------+----------------+-----------------------------------------------------------------------------------------------------------------+
|          | Description    | Mandatory                                                                                                       |
+==========+================+=================================================================================================================+
| username | User name.     | Mandatory if requests_negotiate_sspi module is not installed. In such a case requests_ntlm module is mandatory. |
+----------+----------------+-----------------------------------------------------------------------------------------------------------------+
| password | User password. | Mandatory if requests_negotiate_sspi module is not installed. In such a case requests_ntlm module is mandatory. |
+----------+----------------+-----------------------------------------------------------------------------------------------------------------+

Multiple authentication at once
===============================

You can also use a combination of authentication as in the following sample:

.. code:: python

    import requests
    from requests_auth import Auths, HeaderApiKey, OAuth2

    api_key = HeaderApiKey('my_api_key')
    oauth2 = OAuth2('https://www.example.com')
    requests.get('http://www.example.com', auth=Auths(api_key, oauth2))

.. _requests module: https://pypi.python.org/pypi/requests
.. _authentication parameter on requests module: http://docs.python-requests.org/en/master/user/authentication/
.. _OpenID ID Token specifications: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
.. _requests-negotiate-sspi module: https://pypi.python.org/pypi/requests-negotiate-sspi
.. _requests_ntlm module: https://pypi.python.org/pypi/requests_ntlm
