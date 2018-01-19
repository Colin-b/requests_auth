# Easy Authentication for Requests #

This module provides you authentication classes to be used with [`requests`][1].

To use a specific authentication in combination with requests, use the [authentication parameter on `requests` module][2].

## OAuth 2 ##

Sample:

```python
import requests
from requests_auth.authentication import OAuth2

requests.get('http://www.example.com', auth=OAuth2('https://www.example.com'))
```

### Parameters ###

<table>
    <th>
        <td><em>Description</em></td>
        <td><em>Mandatory</em></td>
        <td><em>Default value</em></td>
    </th>
    <tr>
        <td><strong>authorization_url</strong></td>
        <td>OAuth 2 authorization URL.</td>
        <td>Mandatory</td>
        <td></td>
    </tr>
    <tr>
        <td><strong>redirect_uri_endpoint</strong></td>
        <td>Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>.</td>
        <td>Optional</td>
        <td>''</td>
    </tr>
    <tr>
        <td><strong>redirect_uri_port</strong></td>
        <td>The port on which the server listening for the OAuth 2 token will be started.</td>
        <td>Optional</td>
        <td>5000</td>
    </tr>
    <tr>
        <td><strong>redirect_uri_port_availability_timeout</strong></td>
        <td>The maximum amount of seconds to wait for the redirect_uri_port to become available.</td>
        <td>Optional</td>
        <td>2</td>
    </tr>
    <tr>
        <td><strong>token_reception_timeout</strong></td>
        <td>Maximum amount of seconds to wait for a token to be received once requested.</td>
        <td>Optional</td>
        <td>60</td>
    </tr>
    <tr>
        <td><strong>token_reception_success_display_time</strong></td>
        <td>In case a token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser.</td>
        <td>Optional</td>
        <td>1</td>
    </tr>
    <tr>
        <td><strong>token_reception_failure_display_time</strong></td>
        <td>In case received token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser.</td>
        <td>Optional</td>
        <td>5000</td>
    </tr>
    <tr>
        <td><strong>any other parameter</strong></td>
        <td>all additional authorization parameters that should be put as query parameter in the authorization URL.        
        Common parameters are:
        
 * client_id: Corresponding to your Application ID (in Microsoft Azure app portal)
 * response_type: id_token for Microsoft
 * nonce: Refer to [OpenID ID Token specifications][3] for more details</td>
        <td>Optional</td>
        <td></td>
    </tr>
</table>

### Managing token cache ###

To avoid asking for a new token every new request, a token cache is used.

Default cache is in memory but it is also possible to use a physical cache using the following method:

```python
from requests_auth.authentication import OAuth2
from requests_auth.oauth2_tokens import JsonTokenFileCache

OAuth2.token_cache = JsonTokenFileCache('my_token_cache')
```

### Common OAuth2 providers ###

#### Microsoft ####

Sample:

```python
import requests
from requests_auth.authentication import MicrosoftOAuth2


ms_auth = MicrosoftOAuth2(tenant_id='45239d18-c68c-4c47-8bdd-ce71ea1d50cd', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', nonce='7362CAEA-9CA5-4B43-9BA3-34D7C303EBA7')
requests.get('http://www.example.com', auth=ms_auth)
```

##### Parameters #####

<table>
    <th>
        <td><em>Description</em></td>
        <td><em>Mandatory</em></td>
        <td><em>Default value</em></td>
    </th>
    <tr>
        <td><strong>tenant_id</strong></td>
        <td>Microsoft Tenant Identifier (formatted as 45239d18-c68c-4c47-8bdd-ce71ea1d50cd).</td>
        <td>Mandatory</td>
        <td></td>
    </tr>
    <tr>
        <td><strong>client_id</strong></td>
        <td>Microsoft Application Identifier (formatted as 45239d18-c68c-4c47-8bdd-ce71ea1d50cd).</td>
        <td>Mandatory</td>
        <td></td>
    </tr>
    <tr>
        <td><strong>nonce</strong></td>
        <td>Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details (formatted as 7362CAEA-9CA5-4B43-9BA3-34D7C303EBA7)</td>
        <td>Mandatory</td>
        <td></td>
    </tr>
    <tr>
        <td><strong>redirect_uri_endpoint</strong></td>
        <td>Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>.</td>
        <td>Optional</td>
        <td>''</td>
    </tr>
    <tr>
        <td><strong>redirect_uri_port</strong></td>
        <td>The port on which the server listening for the OAuth 2 token will be started.</td>
        <td>Optional</td>
        <td>5000</td>
    </tr>
    <tr>
        <td><strong>redirect_uri_port_availability_timeout</strong></td>
        <td>The maximum amount of seconds to wait for the redirect_uri_port to become available.</td>
        <td>Optional</td>
        <td>2</td>
    </tr>
    <tr>
        <td><strong>token_reception_timeout</strong></td>
        <td>Maximum amount of seconds to wait for a token to be received once requested.</td>
        <td>Optional</td>
        <td>60</td>
    </tr>
    <tr>
        <td><strong>token_reception_success_display_time</strong></td>
        <td>In case a token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser.</td>
        <td>Optional</td>
        <td>1</td>
    </tr>
    <tr>
        <td><strong>token_reception_failure_display_time</strong></td>
        <td>In case received token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser.</td>
        <td>Optional</td>
        <td>5000</td>
    </tr>
    <tr>
        <td><strong>any other parameter</strong></td>
        <td>all additional authorization parameters that should be put as query parameter in the authorization URL.</td>
        <td>Optional</td>
        <td></td>
    </tr>
</table>

## API key in header ##

Sample:

```python
import requests
from requests_auth.authentication import HeaderApiKey

requests.get('http://www.example.com', auth=HeaderApiKey('my_api_key'))
```

### Parameters ###

<table>
    <th>
        <td><em>Description</em></td>
        <td><em>Mandatory</em></td>
        <td><em>Default value</em></td>
    </th>
    <tr>
        <td><strong>api_key</strong></td>
        <td>The API key that will be sent.</td>
        <td>Mandatory</td>
        <td></td>
    </tr>
    <tr>
        <td><strong>header_name</strong></td>
        <td>Name of the header field.</td>
        <td>Optional</td>
        <td>"X-API-Key"</td>
    </tr>
</table>

## API key in query ##

Sample:

```python
import requests
from requests_auth.authentication import QueryApiKey

requests.get('http://www.example.com', auth=QueryApiKey('my_api_key'))
```

### Parameters ###

<table>
    <th>
        <td><em>Description</em></td>
        <td><em>Mandatory</em></td>
        <td><em>Default value</em></td>
    </th>
    <tr>
        <td><strong>api_key</strong></td>
        <td>The API key that will be sent.</td>
        <td>Mandatory</td>
        <td></td>
    </tr>
    <tr>
        <td><strong>query_parameter_name</strong></td>
        <td>Name of the query parameter.</td>
        <td>Optional</td>
        <td>"api_key"</td>
    </tr>
</table>

## Basic ##

Sample:

```python
import requests
from requests_auth.authentication import Basic

requests.get('http://www.example.com', auth=Basic('username', 'password'))
```

### Parameters ###

<table>
    <th>
        <td><em>Description</em></td>
        <td><em>Mandatory</em></td>
        <td><em>Default value</em></td>
    </th>
    <tr>
        <td><strong>username</strong></td>
        <td>User name.</td>
        <td>Mandatory</td>
        <td></td>
    </tr>
    <tr>
        <td><strong>password</strong></td>
        <td>User password.</td>
        <td>Mandatory</td>
        <td></td>
    </tr>
</table>

## NTLM ##

Requires [requests-negotiate-sspi module][4] or [requests_ntlm module][5] depending on provided parameters.

Sample:

```python
import requests
from requests_auth.authentication import NTLM

requests.get('http://www.example.com', auth=NTLM())
```

### Parameters ###

<table>
    <th>
        <td><em>Description</em></td>
        <td><em>Mandatory</em></td>
        <td><em>Default value</em></td>
    </th>
    <tr>
        <td><strong>username</strong></td>
        <td>User name.</td>
        <td>Mandatory if requests_negotiate_sspi module is not installed. In such a case requests_ntlm module is mandatory.</td>
        <td></td>
    </tr>
    <tr>
        <td><strong>password</strong></td>
        <td>User password.</td>
        <td>Mandatory if requests_negotiate_sspi module is not installed. In such a case requests_ntlm module is mandatory.</td>
        <td></td>
    </tr>
</table>

## Multiple authentication at once ##

You can also use a combination of authentication as in the following sample:

```python
import requests
from requests_auth.authentication import Auths, HeaderApiKey, OAuth2

api_key = HeaderApiKey('my_api_key')
oauth2 = OAuth2('https://www.example.com')
requests.get('http://www.example.com', auth=Auths([api_key, oauth2]))
```

[1]: https://pypi.python.org/pypi/requests "requests module"
[2]: http://docs.python-requests.org/en/master/user/authentication/ "authentication parameter on requests module"
[3]: http://openid.net/specs/openid-connect-core-1_0.html#IDToken "OpenID ID Token specifications"
[4]: https://pypi.python.org/pypi/requests-negotiate-sspi "requests-negotiate-sspi module"
[5]: https://pypi.python.org/pypi/requests_ntlm "requests_ntlm module"
