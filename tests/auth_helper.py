import requests
from responses import RequestsMock


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
