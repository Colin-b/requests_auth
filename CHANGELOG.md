# Requests Authentication Changelog #

List all changes in various categories:
* Release notes: Contains all worth noting changes (breaking changes mainly)
* Enhancements
* Bug fixes
* Known issues

## 4.1.0 (2019-04-01) ##

### Enhancements ###

- module version is now publicly available.
- multiple authentication is now possible using "+" sign.

### Deprecated ###

- Auths class will be considered as internal in the future and should not be used anymore. Use "+" instead.

## 4.0.1 (2018-12-16) ##

### Bug fixes ###

- Update requests dependency to the latest version.
- Update the packaging to render Markdown on pypi.

## 4.0.0 (2018-12-16) ##

### Release notes ###

- str representation of authentication classes are not prefixed by "authentication." anymore.
- [OAuth2] Implicit flow is now expecting token in access_token field by default (or id_token if response_type is id_token). This can be overridden thanks to new token_field_name parameter. Previous behavior was to expect a token named the same way than response_type (or token)
- [OAuth2] Authorization code flow provides a new code_field_name parameter to know in what field code should be expected. Default value is code. Previous behavior was to expect a code named the same way than response_type (or code)
- [Azure AD] Implicit class now provides Access Token by default. Use new IdToken class to request OpenID Connect ID Token.
- [Okta] Implicit class now provides Access Token by default. Use new IdToken class to request OpenID Connect ID Token.

### Bug fixes ###

- [OAuth2] Implicit flow is now ensuring that response_type is set in query. Default value is token.
- [OAuth2] Authorization code flow is now ensuring that response_type is set in query. Default value is token.
- [Azure AD] Allow to override response_type.
- [Azure AD] Allow to override expected token name.
- [Okta] Allow to override expected token name.

## 3.0.0 (2018-11-13) ##

### Release notes ###

- All previously existing OAuth2 related classes renamed to state that it corresponds to implicit flow.
- [Okta] scopes parameter merged with scope.

### Bug fixes ###

- Update requests dependency to latest version (2.20.1)
- [OAuth2] Remove unused redirect_uri_port_availability_timeout parameter

## 2.0.0 (2018-10-09) ##

### Release notes ###

- OAuth2 token is now provided by default in Authorization header.
- Auths does not take a list anymore but a var args instead.
- MicrosoftOAuth2 renamed into AzureActiveDirectory.
- Nonce is not a mandatory parameter anymore for MicrosoftOAuth2.

### Enhancements ###

- Authentication classes can now be imported from requests_auth.
- JSONTokenFileCache can now be imported from requests_auth.
- Okta authentication is now available (thanks to Sebastien De Menten).

### Bug fixes ###

- Oauth2 authentication was not working with Python 2.7
- Update requests to 2.19.1 (latest version)
- OAuth2 authentication now supports GET on token reception (thanks to Sebastien De Menten).
- Extra parameters were not handled when using MicrosoftOAuth2 (now AzureActiveDirectory)

## 1.0.2 (2018-01-19) ##

### Release notes ###

- Public release
