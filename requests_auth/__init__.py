from enum import Enum, auto

from .authentication import (
    Basic,
    HeaderApiKey,
    QueryApiKey,
    NTLM,
    Auths,

    OAuth2,

    OAuth2Implicit,
    OktaImplicit,
    AzureActiveDirectoryImplicit,

    OAuth2AuthorizationCode,

    OAuth2ClientCredentials,
    OAuth2ResourceOwnerPasswordCredentials,
)
from .oauth2_tokens import JsonTokenFileCache


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
