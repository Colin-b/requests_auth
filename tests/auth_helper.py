import requests
from responses import RequestsMock, Response


def get_header(responses: RequestsMock, auth):
    # Mock a dummy response
    responses.add(responses.GET, "http://authorized_only")
    # Send a request to this dummy URL with authentication
    response = requests.get("http://authorized_only", auth=auth)
    # Return headers received on this dummy URL
    return response.request.headers


def get_query_args(responses: RequestsMock, auth):
    # Mock a dummy response
    responses.add(responses.GET, "http://authorized_only")
    # Send a request to this dummy URL with authentication
    response = requests.get("http://authorized_only", auth=auth)
    # Return headers received on this dummy URL
    return response.request.path_url


def get_request(responses: RequestsMock, url: str) -> Response:
    for call in responses.calls:
        if call.request.url == url:
            # Pop out verified request (to be able to check multiple requests)
            responses.calls._calls.remove(call)
            return call.request
