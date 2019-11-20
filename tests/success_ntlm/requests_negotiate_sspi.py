class HttpNegotiateAuth:
    def __call__(self, r):
        r.headers["Authorization"] = "HttpNegotiateAuth fake"
