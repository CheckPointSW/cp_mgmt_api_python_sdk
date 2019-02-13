class APIException(Exception):
    """An exception subclass for our API exceptions, also includes the response when available."""
    def __init__(self, value, response):
        self.value = value
        self.response = response

    def __str__(self):
        return str(self.value)


class APIClientException(APIException):
    def __init__(self, value):
        APIException.__init__(self, value, None)

