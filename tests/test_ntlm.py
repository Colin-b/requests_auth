import os

import pytest
import requests
from responses.matchers import header_matcher

import requests_auth


def test_requests_negotiate_sspi_is_used_when_nothing_is_provided_but_without_installed(
    monkeypatch,
):
    # load requests_negociate_sspi from the file in tests/failing_ntlm folder
    monkeypatch.syspath_prepend(
        os.path.join(os.path.abspath(os.path.dirname(__file__)), "failing_ntlm")
    )
    with pytest.raises(Exception) as exception_info:
        requests_auth.NTLM()
    assert (
        str(exception_info.value)
        == "NTLM authentication requires requests_negotiate_sspi module."
    )


def test_requests_negotiate_sspi_is_used_when_nothing_is_provided(
    monkeypatch, responses
):
    # load requests_negociate_sspi from the file in tests/success_ntlm folder
    monkeypatch.syspath_prepend(
        os.path.join(os.path.abspath(os.path.dirname(__file__)), "success_ntlm")
    )
    auth = requests_auth.NTLM()

    responses.get(
        "http://authorized_only",
        match=[header_matcher({"Authorization": "HttpNegotiateAuth fake"})],
    )

    requests.get("http://authorized_only", auth=auth)


def test_requests_ntlm_is_used_when_user_and_pass_provided_but_without_installed(
    monkeypatch,
):
    # load requests_ntlm from the file in tests/failing_ntlm folder
    monkeypatch.syspath_prepend(
        os.path.join(os.path.abspath(os.path.dirname(__file__)), "failing_ntlm")
    )
    with pytest.raises(Exception) as exception_info:
        requests_auth.NTLM("fake_user", "fake_pwd")
    assert (
        str(exception_info.value)
        == "NTLM authentication requires requests_ntlm module."
    )


def test_requests_ntlm_is_used_when_user_and_pass_provided(monkeypatch, responses):
    # load requests_ntlm from the file in tests/success_ntlm folder
    monkeypatch.syspath_prepend(
        os.path.join(os.path.abspath(os.path.dirname(__file__)), "success_ntlm")
    )
    auth = requests_auth.NTLM("fake_user", "fake_pwd")

    responses.get(
        "http://authorized_only",
        match=[
            header_matcher({"Authorization": "HttpNtlmAuth fake fake_user / fake_pwd"})
        ],
    )

    requests.get("http://authorized_only", auth=auth)


def test_user_without_password_is_invalid():
    with pytest.raises(Exception) as exception_info:
        requests_auth.NTLM("fake_user")
    assert (
        str(exception_info.value)
        == 'NTLM authentication requires "password" to be provided in security_details.'
    )


def test_password_without_user_is_invalid():
    with pytest.raises(Exception) as exception_info:
        requests_auth.NTLM(password="fake_pwd")
    assert (
        str(exception_info.value)
        == 'NTLM authentication requires "username" to be provided in security_details.'
    )
