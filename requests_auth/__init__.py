from enum import Enum, auto

from .authentication import (
    Basic,
    HeaderApiKey,
    QueryApiKey,
    NTLM,
    Auths,

    OAuth2Implicit,
    OktaImplicit,
    AzureActiveDirectoryImplicit,
)
from .oauth2_tokens import JsonTokenFileCache


class OAuth2Flow(Enum):
    Implicit = auto(),


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
