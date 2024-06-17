class HttpNtlmAuth:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __call__(self, r):
        r.headers["Authorization"] = (
            f"HttpNtlmAuth fake {self.username} / {self.password}"
        )
