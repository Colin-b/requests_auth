<h2 align="center">Easy Authentication for Requests</h2>

<p align="center">
<a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
</p>

This module provides you authentication classes to be used with [`requests`][1].

To use a specific authentication in combination with requests, use the [authentication parameter on `requests` module][2].  

## Contents

- [OAuth2](#oauth-2)
  - [Authorization Code Flow](#authorization-code-flow)
  - [PKCE Flow](#proof-key-for-code-exchange-flow)
  - [Resource Owner Password Credentials flow](#resource-owner-password-credentials-flow)
  - [Client Credentials Flow](#client-credentials-flow)
  - [Implicit Flow](#implicit-flow)
    - [Azure AD (Access Token)](#microsoft---azure-active-directory-oauth2-access-token)
    - [Azure AD (ID token)](#microsoft---azure-active-directory-openid-connect-id-token)
    - [OKTA (Access Token)](#okta-oauth2-access-token)
    - [OKTA (ID token)](#okta-openid-connect-id-token)
  - [Managing token cache](#managing-token-cache)
- API key
  - [In header](#api-key-in-header)
  - [In query](#api-key-in-query)
- [Basic](#basic)
- [NTLM (Windows)](#ntlm)
- [Multiple authentication at once](#multiple-authentication-at-once)

## OAuth 2

### Authorization Code flow

Sample:

```python
import requests
from requests_auth import OAuth2AuthorizationCode

requests.get('http://www.example.com', auth=OAuth2AuthorizationCode('https://www.authorization.url', 'https://www.token.url'))
```

or

```python
import requests
from requests_auth import oauth2, OAuth2Flow

requests.get('http://www.example.com', auth=oauth2(OAuth2Flow.AuthorizationCode, 'https://www.authorization.url', 'https://www.token.url'))
```

#### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `authorization_url`     | OAuth 2 authorization URL. | Mandatory |               |
| `token_url`             | OAuth 2 token URL.         | Mandatory |               |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. | Optional | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 code will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a code or a token to be received once requested. | Optional | 60 |
| `success_display_time`  | In case a code is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser. | Optional | 1 |
| `failure_display_time`  | In case received code is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser. | Optional | 5000 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | code |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `code_field_name`       | Field name containing the code. | Optional | code |
| `username`              | User name in case basic authentication should be used to retrieve token. | Optional |  |
| `password`              | User password in case basic authentication should be used to retrieve token. | Optional |  |

Any other parameter will be put as query parameter in the authorization URL and as body parameters in the token URL.        

Usual parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `client_id`     | Corresponding to your Application ID (in Microsoft Azure app portal) |
| `client_secret` | If client is not authenticated with the authorization server         |
| `nonce`         | Refer to [OpenID ID Token specifications][3] for more details        |

### Proof Key for Code Exchange flow

Sample:

```python
import requests
from requests_auth import OAuth2PKCE

requests.get('http://www.example.com', auth=OAuth2PKCE('https://www.authorization.url', 'https://www.token.url'))
```

or

```python
import requests
from requests_auth import oauth2, OAuth2Flow

requests.get('http://www.example.com', auth=oauth2(OAuth2Flow.PKCE, 'https://www.authorization.url', 'https://www.token.url'))
```

#### Parameters 

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `authorization_url`     | OAuth 2 authorization URL. | Mandatory |               |
| `token_url`             | OAuth 2 token URL.         | Mandatory |               |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. | Optional | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 code will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a code or a token to be received once requested. | Optional | 60 |
| `success_display_time`  | In case a code is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser. | Optional | 1 |
| `failure_display_time`  | In case received code is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser. | Optional | 5000 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | code |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `code_field_name`       | Field name containing the code. | Optional | code |

Any other parameter will be put as query parameter in the authorization URL and as body parameters in the token URL.        

Usual parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `client_id`     | Corresponding to your Application ID (in Microsoft Azure app portal) |
| `client_secret` | If client is not authenticated with the authorization server         |
| `nonce`         | Refer to [OpenID ID Token specifications][3] for more details        |

### Resource Owner Password Credentials flow 

Sample:

```python
import requests
from requests_auth import OAuth2ResourceOwnerPasswordCredentials

requests.get('http://www.example.com', auth=OAuth2ResourceOwnerPasswordCredentials('https://www.token.url', 'user name', 'user password'))
```

or

```python
import requests
from requests_auth import oauth2, OAuth2Flow

requests.get('http://www.example.com', auth=oauth2(OAuth2Flow.PasswordCredentials, 'https://www.token.url', 'user name', 'user password'))
```

#### Parameters

| Name               | Description                                  | Mandatory | Default value |
|:-------------------|:---------------------------------------------|:----------|:--------------|
| `token_url`        | OAuth 2 token URL.                           | Mandatory |               |
| `username`         | Resource owner user name.                    | Mandatory |               |
| `password`         | Resource owner password.                     | Mandatory |               |
| `timeout`          | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60            |
| `header_name`      | Name of the header field used to send token. | Optional  | Authorization |
| `header_value`     | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |
| `scope`            | Scope parameter sent to token URL as body. Can also be a list of scopes. | Optional |  |
| `token_field_name` | Field name containing the token.             | Optional  | access_token  |

Any other parameter will be put as body parameter in the token URL.

### Client Credentials flow

Sample:

```python
import requests
from requests_auth import OAuth2ClientCredentials

requests.get('http://www.example.com', auth=OAuth2ClientCredentials('https://www.token.url', 'user name', 'user password'))
```

or

```python
import requests
from requests_auth import oauth2, OAuth2Flow

requests.get('http://www.example.com', auth=oauth2(OAuth2Flow.ClientCredentials, 'https://www.token.url', 'user name', 'user password'))
```

#### Parameters

| Name               | Description                                  | Mandatory | Default value |
|:-------------------|:---------------------------------------------|:----------|:--------------|
| `token_url`        | OAuth 2 token URL.                           | Mandatory |               |
| `username`         | Resource owner user name.                    | Mandatory |               |
| `password`         | Resource owner password.                     | Mandatory |               |
| `timeout`          | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60            |
| `header_name`      | Name of the header field used to send token. | Optional  | Authorization |
| `header_value`     | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |
| `scope`            | Scope parameter sent to token URL as body. Can also be a list of scopes. | Optional |  |
| `token_field_name` | Field name containing the token.             | Optional  | access_token  |

Any other parameter will be put as body parameter in the token URL.

### Implicit flow

Sample:

```python
import requests
from requests_auth import OAuth2Implicit

requests.get('http://www.example.com', auth=OAuth2Implicit('https://www.authorization.url'))
```

or

```python
import requests
from requests_auth import oauth2, OAuth2Flow

requests.get('http://www.example.com', auth=oauth2(OAuth2Flow.Implicit, 'https://www.authorization.url'))
```

#### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `authorization_url`     | OAuth 2 authorization URL. | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | token |
| `token_field_name`      | Field name containing the token. | Optional | id_token if response_type is id_token, otherwise access_token |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. | Optional | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `success_display_time`  | In case a token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser. | Optional | 1 |
| `failure_display_time`  | In case received token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser. | Optional | 5000 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual parameters are:

| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `client_id`     | Corresponding to your Application ID (in Microsoft Azure app portal) |
| `nonce`         | Refer to [OpenID ID Token specifications][3] for more details        |
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

#### Common providers

##### Microsoft - Azure Active Directory (OAuth2 Access Token)

Sample:

```python
import requests
from requests_auth import AzureActiveDirectoryImplicit


aad = AzureActiveDirectoryImplicit(tenant_id='45239d18-c68c-4c47-8bdd-ce71ea1d50cd', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
requests.get('http://www.example.com', auth=aad)
```

or

```python
import requests
from requests_auth import aad, OAuth2Flow

requests.get('http://www.example.com', auth=aad(OAuth2Flow.Implicit, tenant_id='45239d18-c68c-4c47-8bdd-ce71ea1d50cd', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd'))
```

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `tenant_id`             | Microsoft Tenant Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `client_id`             | Microsoft Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | token |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details | Optional | Newly generated Universal Unique Identifier. |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. | Optional | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `success_display_time`  | In case a token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser. | Optional | 1 |
| `failure_display_time`  | In case received token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser. | Optional | 5000 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual parameters are:

| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

##### Microsoft - Azure Active Directory (OpenID Connect ID token)

Sample:

```python
import requests
from requests_auth import AzureActiveDirectoryImplicitIdToken


aad = AzureActiveDirectoryImplicitIdToken(tenant_id='45239d18-c68c-4c47-8bdd-ce71ea1d50cd', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
requests.get('http://www.example.com', auth=aad)
```

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `tenant_id`             | Microsoft Tenant Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `client_id`             | Microsoft Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | id_token |
| `token_field_name`      | Field name containing the token. | Optional | id_token |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details | Optional | Newly generated Universal Unique Identifier. |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. | Optional | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `success_display_time`  | In case a token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser. | Optional | 1 |
| `failure_display_time`  | In case received token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser. | Optional | 5000 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual parameters are:

| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

##### OKTA (OAuth2 Access Token)

Sample:

```python
import requests
from requests_auth import OktaImplicit


okta = OktaImplicit(instance='testserver.okta-emea.com', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
requests.get('http://www.example.com', auth=okta)
```

or

```python
import requests
from requests_auth import okta, OAuth2Flow

requests.get('http://www.example.com', auth=okta(OAuth2Flow.Implicit, instance='testserver.okta-emea.com', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd'))
```

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `instance`              | OKTA instance (like "testserver.okta-emea.com"). | Mandatory |               |
| `client_id`             | Microsoft Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | token |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details. | Optional | Newly generated Universal Unique Identifier. |
| `scope`                 | Scope parameter sent in query. Can also be a list of scopes. | Optional | ['openid', 'profile', 'email'] |
| `authorization_server`  | OKTA authorization server. | Optional | 'default' |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. | Optional | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `success_display_time`  | In case a token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser. | Optional | 1 |
| `failure_display_time`  | In case received token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser. | Optional | 5000 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual parameters are:

| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

##### OKTA (OpenID Connect ID token)

Sample:

```python
import requests
from requests_auth import OktaImplicitIdToken


okta = OktaImplicitIdToken(instance='testserver.okta-emea.com', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
requests.get('http://www.example.com', auth=okta)
```

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `instance`              | OKTA instance (like "testserver.okta-emea.com"). | Mandatory |               |
| `client_id`             | Microsoft Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | id_token |
| `token_field_name`      | Field name containing the token. | Optional | id_token |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details. | Optional | Newly generated Universal Unique Identifier. |
| `scope`                 | Scope parameter sent in query. Can also be a list of scopes. | Optional | ['openid', 'profile', 'email'] |
| `authorization_server`  | OKTA authorization server. | Optional | 'default' |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. | Optional | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `success_display_time`  | In case a token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser. | Optional | 1 |
| `failure_display_time`  | In case received token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser. | Optional | 5000 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual parameters are:

| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

### Managing token cache

To avoid asking for a new token every new request, a token cache is used.

Default cache is in memory but it is also possible to use a physical cache using the following method:

```python
from requests_auth import OAuth2, JsonTokenFileCache

OAuth2.token_cache = JsonTokenFileCache('my_token_cache')
```


## API key in header

Sample:

```python
import requests
from requests_auth import HeaderApiKey

requests.get('http://www.example.com', auth=HeaderApiKey('my_api_key'))
```

### Parameters

| Name                    | Description                    | Mandatory | Default value |
|:------------------------|:-------------------------------|:----------|:--------------|
| `api_key`               | The API key that will be sent. | Mandatory |               |
| `header_name`           | Name of the header field.      | Optional  | "X-API-Key"   |

## API key in query

Sample:

```python
import requests
from requests_auth import QueryApiKey

requests.get('http://www.example.com', auth=QueryApiKey('my_api_key'))
```

### Parameters

| Name                    | Description                    | Mandatory | Default value |
|:------------------------|:-------------------------------|:----------|:--------------|
| `api_key`               | The API key that will be sent. | Mandatory |               |
| `query_parameter_name`  | Name of the query parameter.   | Optional  | "api_key"     |

## Basic

Sample:

```python
import requests
from requests_auth import Basic

requests.get('http://www.example.com', auth=Basic('username', 'password'))
```

### Parameters

| Name                    | Description                    | Mandatory | Default value |
|:------------------------|:-------------------------------|:----------|:--------------|
| `username`              | User name.                     | Mandatory |               |
| `password`              | User password.                 | Mandatory |               |

## NTLM

Requires [requests-negotiate-sspi module][4] or [requests_ntlm module][5] depending on provided parameters.

Sample:

```python
import requests
from requests_auth import NTLM

requests.get('http://www.example.com', auth=NTLM())
```

### Parameters

| Name                    | Description                    | Mandatory | Default value |
|:------------------------|:-------------------------------|:----------|:--------------|
| `username`              | User name.                     | Mandatory if requests_negotiate_sspi module is not installed. In such a case requests_ntlm module is mandatory. |               |
| `password`              | User password.                 | Mandatory if requests_negotiate_sspi module is not installed. In such a case requests_ntlm module is mandatory. |               |

## Multiple authentication at once

You can also use a combination of authentication using `+` as in the following sample:

```python
import requests
from requests_auth import HeaderApiKey, OAuth2Implicit

api_key = HeaderApiKey('my_api_key')
oauth2 = OAuth2Implicit('https://www.example.com')
requests.get('http://www.example.com', auth=api_key + oauth2)
```

[1]: https://pypi.python.org/pypi/requests "requests module"
[2]: http://docs.python-requests.org/en/master/user/authentication/ "authentication parameter on requests module"
[3]: http://openid.net/specs/openid-connect-core-1_0.html#IDToken "OpenID ID Token specifications"
[4]: https://pypi.python.org/pypi/requests-negotiate-sspi "requests-negotiate-sspi module"
[5]: https://pypi.python.org/pypi/requests_ntlm "requests_ntlm module"
