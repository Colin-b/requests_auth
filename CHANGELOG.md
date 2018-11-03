# Requests Authentication Changelog #

List all changes in various categories:
* Release notes: Contains all worth noting changes (breaking changes mainly)
* Enhancements
* Bug fixes
* Known issues

## 3.0.0 (2018-11-03) ##

### Release notes ###

- All previously existing OAuth2 related classes renamed to state that it corresponds to implicit flow.

### Bug fixes ###

- Update requests dependency to latest version (2.20.0)

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
