# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [8.0.0] - 2024-06-18
### Added
- Adding explicit support for Python `3.12`.
- Publicly expose `requests_auth.SupportMultiAuth`, allowing multiple authentication support for every `requests` authentication class that exists.
- Publicly expose `requests_auth.TokenMemoryCache`, allowing to create custom Oauth2 token cache based on this default implementation.
- You can now provide your own HTML success (`success_html`) and failure (`failure_html`) display via the new `OAuth2.display` shared setting. Refer to documentation for more details.
- Thanks to the new `redirect_uri_domain` parameter on Authorization code (with and without PKCE) and Implicit flows, you can now provide the [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the `redirect_uri` when `localhost` (the default) is not allowed.
- `requests_auth.WakaTimeAuthorizationCode` handling access to the [WakaTime API](https://wakatime.com/developers).

### Changed
- Except for `requests_auth.testing`, only direct access via `requests_auth.` was considered publicly exposed. This is now explicit, as inner packages are now using private prefix (`_`).
  If you were relying on some classes or functions that are now internal, feel free to open an issue.
- `requests_auth.JsonTokenFileCache` and `requests_auth.TokenMemoryCache` `get_token` method does not handle kwargs anymore, the `on_missing_token` callable does not expect any arguments anymore.
- `requests_auth.JsonTokenFileCache` does not expose `tokens_path` or `last_save_time` attributes anymore and is also allowing `pathlib.Path` instances as cache location.
- `requests_auth.TokenMemoryCache` does not expose `forbid_concurrent_cache_access` or `forbid_concurrent_missing_token_function_call` attributes anymore.
- Browser display settings have been moved to a shared setting, see documentation for more information on `requests_auth.OAuth2.display`.
  The failure page will be displayed for 10 seconds by default instead of 5 seconds previously.
  As a result the following classes no longer expose `success_display_time` and `failure_display_time` parameters.
  - `requests_auth.OAuth2AuthorizationCode`.
  - `requests_auth.OktaAuthorizationCode`.
  - `requests_auth.WakaTimeAuthorizationCode`.
  - `requests_auth.OAuth2AuthorizationCodePKCE`.
  - `requests_auth.OktaAuthorizationCodePKCE`.
  - `requests_auth.OAuth2Implicit`.
  - `requests_auth.AzureActiveDirectoryImplicit`.
  - `requests_auth.AzureActiveDirectoryImplicitIdToken`.
  - `requests_auth.OktaImplicit`.
  - `requests_auth.OktaImplicitIdToken`.
- The authentication success and failure displayed in the browser were revamped to be more user-friendly. `requests_auth.testing` was modified to accommodate this change:
  - `tab.assert_success` `expected_message` parameter was removed.
  - `tab.assert_failure` `expected_message` parameter should not be prefixed with `Unable to properly perform authentication: ` anymore and `\n` in the message should be replaced with `<br>`.
- Exceptions issued by `requests_auth` are now inheriting from `requests_auth.RequestsAuthException`, itself inheriting from `requests.RequestException`, instead of `Exception`.

### Fixed
- Type information is now provided following [PEP 561](https://www.python.org/dev/peps/pep-0561/).
- Remove deprecation warnings due to usage of `utcnow` and `utcfromtimestamp`.
- `requests_auth.OktaClientCredentials` `scope` parameter is now mandatory and does not default to `openid` anymore.
- `requests_auth.OktaClientCredentials` will now display a more user-friendly error message in case Okta instance is not provided.
- Tokens cache `DEBUG` logs will not display tokens anymore.
- Handle `text/html; charset=utf-8` content-type in token responses.

### Removed
- Removing support for Python `3.7`.
- Deprecated `requests_auth.Auths` class has been removed.

## [7.0.0] - 2023-04-27
### Changed
- `requests_auth.OAuth2ResourceOwnerPasswordCredentials` does not send basic authentication by default.

### Added
- `session_auth` as a parameter of `requests_auth.OAuth2ResourceOwnerPasswordCredentials`. Allowing to provide any kind of optional authentication.
- `requests_auth.OktaResourceOwnerPasswordCredentials` providing Okta resource owner password credentials flow easy setup.
- Explicit support for Python `3.11`.

### Removed
- Explicit support for Python `3.6`.

## [6.0.0] - 2022-01-11
### Changed
- `requests_auth.oauth2_tokens.TokenMemoryCache.get_token` method now requires arguments to be named.
- `requests_auth.oauth2_tokens.TokenMemoryCache.get_token` method `on_missing_token` arguments must now be named (switched from args to kwargs).
- `requests_auth.JsonTokenFileCache.get_token` method now requires arguments to be named.
- `requests_auth.JsonTokenFileCache.get_token` method `on_missing_token` arguments must now be named (switched from args to kwargs).
- `requests_auth.testing` now requires `pyjwt==2.*`.

### Added
- `requests_auth.oauth2_tokens.TokenMemoryCache.get_token` now allows to specify a custom `early_expiry` in seconds (default to 30).
- `requests_auth.JsonTokenFileCache.get_token` now allows to specify a custom `early_expiry` in seconds (default to 30).
- `requests_auth.OAuth2ResourceOwnerPasswordCredentials` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.OAuth2ClientCredentials` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.OktaClientCredentials` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.OAuth2AuthorizationCode` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.OktaAuthorizationCode` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.OAuth2AuthorizationCodePKCE` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.OktaAuthorizationCodePKCE` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.OAuth2Implicit` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.AzureActiveDirectoryImplicit` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.AzureActiveDirectoryImplicitIdToken` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.OktaImplicit` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `requests_auth.OktaImplicitIdToken` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.

### Removed
- `requests_auth.oauth2_tokens.is_expired` is not available anymore.
- `requests_auth.oauth2_tokens.decode_base64` is not available anymore.
- `requests_auth.oauth2_tokens.TokenMemoryCache.add_bearer_token` is not available anymore.
- `requests_auth.oauth2_tokens.TokenMemoryCache.add_access_token` is not available anymore.

### Fixed
- OAuth2 token will now be considered as expired 30 seconds before actual expiry. To ensure it is still valid when received by the actual server.

## [5.3.0] - 2021-06-06
### Added
- Support for refresh tokens in the Resource Owner Password Credentials flow and Authorization Code (with and without PKCE) flows (Thanks to [Stijn Caerts](https://github.com/StijnCaerts)).

## [5.2.0] - 2020-10-14
### Added
- Allow to provide a `requests.Session` instance for `*AuthorizationCode` flows (even `PKCE`), `*ClientCredentials` and `*ResourceOwnerPasswordCredentials` flows.
- Explicit support for Python `3.9`.

### Changed
- Code now follow `black==20.8b1` formatting instead of the git master version.

## [5.1.0] - 2020-03-04
### Added
- [`pytest`](https://docs.pytest.org/en/latest/) fixtures in `requests_auth.testing`. Refer to documentation for more details.

## [5.0.2] - 2019-12-12
### Fixed
- Handle expires_in sent as str instead of int.

## [5.0.1] - 2019-11-28
### Added
- Allow to use & between authentication classes.

### Fixed
- Avoid DeprecationWarning in case multi auth is used with +
- Avoid packaging tests (introduced in 5.0.0)

## [5.0.0] - 2019-11-21
### Changed
- OAuth2ClientCredentials username parameter is now client_id
- OAuth2ClientCredentials password parameter is now client_secret
- requests_auth.InvalidGrantRequest is now raised instead of requests.HTTPError in case a grant request was invalid.
- requests_auth.InvalidGrantRequest is now raised instead of requests_auth.GrantNotProvided in case a browser grant request was invalid.
- There is no info logging anymore. If you want to have those information (browser opening on a specific URL, requests received by the OAUth2 server), you will have to put requests_auth logger to DEBUG.

### Removed
- Support for Python < 3.6
- requests_auth.OAuth2Flow enum, use the proper auth class instead.
- requests_auth.okta function, use the proper auth class instead.
- requests_auth.aad function, use the proper auth class instead.
- requests_auth.oauth2 function, use the proper auth class instead.
- str representation of auth classes.

### Fixed
- timeout parameter can now be a floating point value. (was only integer previously)

## [4.1.0] - 2019-11-13
### Added
- module version is now publicly available.
- multiple authentication is now possible using "+" sign.
- OktaAuthorizationCode is now available.
- OktaClientCredentials is now available.
- OAuth2AuthorizationCodePKCE is now available.
- OktaAuthorizationCodePKCE is now available.
- Exception classes defined in requests_auth.errors are now available via requests_auth.

### Deprecated
- Auths class will be considered as internal in the future and should not be used anymore. Use "+" instead.
- This is the latest release to support Python 2.7, next release will be 3.6+ only.
- requests_auth.errors will be renamed into requests_auth.exceptions in the future.
- str representation of authentication classes will be removed in the future.
- requests_auth.oauth2 function will be removed in the future. Use specific class instead.
- requests_auth.aad function will be removed in the future. Use specific class instead.
- requests_auth.okta function will be removed in the future. Use specific class instead.

### Fixed
- Avoid fixing dependencies to a specific version.
- Expiry is now properly computed for access token.
- It is not possible to provide an empty OKTA authorization_server anymore.

### Changed
- OKTA default value for authorization_server is now default.

## [4.0.1] - 2018-12-16
### Changed
- Update requests dependency to the latest version.

### Fixed
- Update the packaging to render Markdown on pypi.

## [4.0.0] - 2018-12-16
### Changed
- str representation of authentication classes are not prefixed by "authentication." anymore.
- [OAuth2] Implicit flow is now expecting token in access_token field by default (or id_token if response_type is id_token). This can be overridden thanks to new token_field_name parameter. Previous behavior was to expect a token named the same way than response_type (or token)
- [OAuth2] Authorization code flow provides a new code_field_name parameter to know in what field code should be expected. Default value is code. Previous behavior was to expect a code named the same way than response_type (or code)
- [Azure AD] Implicit class now provides Access Token by default. Use new IdToken class to request OpenID Connect ID Token.
- [Okta] Implicit class now provides Access Token by default. Use new IdToken class to request OpenID Connect ID Token.

### Fixed
- [OAuth2] Implicit flow is now ensuring that response_type is set in query. Default value is token.
- [OAuth2] Authorization code flow is now ensuring that response_type is set in query. Default value is token.
- [Azure AD] Allow to override response_type.
- [Azure AD] Allow to override expected token name.
- [Okta] Allow to override expected token name.

## [3.0.0] - 2018-11-13
### Changed
- All previously existing OAuth2 related classes renamed to state that it corresponds to implicit flow.
- [Okta] scopes parameter merged with scope.

### Fixed
- Update requests dependency to latest version (2.20.1)
- [OAuth2] Remove unused redirect_uri_port_availability_timeout parameter

## [2.0.0] - 2018-10-09
### Changed
- OAuth2 token is now provided by default in Authorization header.
- Auths does not take a list anymore but a var args instead.
- MicrosoftOAuth2 renamed into AzureActiveDirectory.
- Nonce is not a mandatory parameter anymore for MicrosoftOAuth2.

### Added
- Authentication classes can now be imported from requests_auth.
- JSONTokenFileCache can now be imported from requests_auth.
- Okta authentication is now available (thanks to Sebastien De Menten).

### Fixed
- Oauth2 authentication was not working with Python 2.7
- Update requests to 2.19.1 (latest version)
- OAuth2 authentication now supports GET on token reception (thanks to Sebastien De Menten).
- Extra parameters were not handled when using MicrosoftOAuth2 (now AzureActiveDirectory)

## [1.0.2] - 2018-01-19

### Added
- Public release

[Unreleased]: https://github.com/Colin-b/requests_auth/compare/v8.0.0...HEAD
[8.0.0]: https://github.com/Colin-b/requests_auth/compare/v7.0.0...v8.0.0
[7.0.0]: https://github.com/Colin-b/requests_auth/compare/v6.0.0...v7.0.0
[6.0.0]: https://github.com/Colin-b/requests_auth/compare/v5.3.0...v6.0.0
[5.3.0]: https://github.com/Colin-b/requests_auth/compare/v5.2.0...v5.3.0
[5.2.0]: https://github.com/Colin-b/requests_auth/compare/v5.1.0...v5.2.0
[5.1.0]: https://github.com/Colin-b/requests_auth/compare/v5.0.2...v5.1.0
[5.0.2]: https://github.com/Colin-b/requests_auth/compare/v5.0.1...v5.0.2
[5.0.1]: https://github.com/Colin-b/requests_auth/compare/v5.0.0...v5.0.1
[5.0.0]: https://github.com/Colin-b/requests_auth/compare/v4.1.0...v5.0.0
[4.1.0]: https://github.com/Colin-b/requests_auth/compare/v4.0.1...v4.1.0
[4.0.1]: https://github.com/Colin-b/requests_auth/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/Colin-b/requests_auth/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/Colin-b/requests_auth/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/Colin-b/requests_auth/compare/v1.0.2...v2.0.0
[1.0.2]: https://github.com/Colin-b/requests_auth/releases/tag/v1.0.2
