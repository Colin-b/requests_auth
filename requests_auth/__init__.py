from enum import Enum, auto

from requests_auth.authentication import (
    Basic,
    HeaderApiKey,
    QueryApiKey,
    NTLM,
    Auths,

    OAuth2,

    OAuth2Implicit,
    OktaImplicit,
    OktaImplicitIdToken,
    AzureActiveDirectoryImplicit,
    AzureActiveDirectoryImplicitIdToken,

    OAuth2AuthorizationCode,
    OktaAuthorizationCode,

    OAuth2ClientCredentials,
    OktaClientCredentials,

    OAuth2ResourceOwnerPasswordCredentials,
)
from requests_auth.oauth2_tokens import JsonTokenFileCache
from requests_auth.version import __version__


class OAuth2Flow(Enum):
    Implicit = auto(),
    PasswordCredentials = auto(),  # Also called Resource Owner Password Credentials
    ClientCredentials = auto(),  # Also called Application
    AuthorizationCode = auto(),  # Also called AccessCode


def oauth2(flow, *args, **kwargs):
    """
    Create a new generic OAuth2 authentication class.

    :param flow: OAuth2 flow
    :param args: all mandatory parameters that should be provided for this flow.
    :param kwargs: optional parameters that can be provided for this flow.
    :return: The newly created OAuth2 authentication class.
    """
    if OAuth2Flow.Implicit == flow:
        return OAuth2Implicit(*args, **kwargs)
    if OAuth2Flow.AuthorizationCode == flow:
        return OAuth2AuthorizationCode(*args, **kwargs)
    if OAuth2Flow.ClientCredentials == flow:
        return OAuth2ClientCredentials(*args, **kwargs)
    if OAuth2Flow.PasswordCredentials == flow:
        return OAuth2ResourceOwnerPasswordCredentials(*args, **kwargs)


def okta(flow, *args, **kwargs):
    """
    Create a new OKTA authentication class.

    :param flow: OAuth2 flow
    :param args: all mandatory parameters that should be provided for this flow.
    :param kwargs: optional parameters that can be provided for this flow.
    :return: The newly created OKTA authentication class.
    """
    if OAuth2Flow.Implicit == flow:
        return OktaImplicit(*args, **kwargs)
    if OAuth2Flow.AuthorizationCode == flow:
        return OktaAuthorizationCode(*args, **kwargs)
    if OAuth2Flow.ClientCredentials == flow:
        return OktaClientCredentials(*args, **kwargs)
    raise Exception('{0} flow is not handled yet in OKTA.'.format(flow))


def aad(flow, *args, **kwargs):
    """
    Create a new Azure Active Directory authentication class.

    :param flow: OAuth2 flow
    :param args: all mandatory parameters that should be provided for this flow.
    :param kwargs: optional parameters that can be provided for this flow.
    :return: The newly created Azure Active Directory authentication class.
    """
    if OAuth2Flow.Implicit == flow:
        return AzureActiveDirectoryImplicit(*args, **kwargs)
    raise Exception('{0} flow is not handled yet in Azure Active Directory.'.format(flow))
