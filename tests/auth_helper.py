import requests
import requests.auth
import responses


def get_header(responses: responses.RequestsMock, auth: requests.auth.AuthBase) -> dict:
    # Mock a dummy response
    responses.add(responses.GET, "http://authorized_only")
    # Send a request to this dummy URL with authentication
    response = requests.get("http://authorized_only", auth=auth)
    # Return headers received on this dummy URL
    return response.request.headers


def get_query_args(
    responses: responses.RequestsMock, auth: requests.auth.AuthBase
) -> str:
    # Mock a dummy response
    responses.add(responses.GET, "http://authorized_only")
    # Send a request to this dummy URL with authentication
    response = requests.get("http://authorized_only", auth=auth)
    # Return headers received on this dummy URL
    return response.request.path_url


def get_request(responses: responses.RequestsMock, url: str) -> responses.Response:
    for call in responses.calls:
        if call.request.url == url:
            # Pop out verified request (to be able to check multiple requests)
            responses.calls._calls.remove(call)
            return call.request
