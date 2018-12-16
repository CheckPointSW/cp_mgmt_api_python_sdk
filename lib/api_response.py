import json
import sys

# compatible import for python 2 and 3
from .api_exceptions import APIException
if sys.version_info >= (3, 0):
    from http.client import HTTPResponse
else:
    from httplib import HTTPResponse


class APIResponse:
    """
    An object to represent an API Response.
    Contains data, status_code, success, and sometimes error_message
    """
    def __repr__(self):
        return "lib::APIResponse\n" + json.dumps(self.as_dict(), indent=4, sort_keys=True)

    def __init__(self, json_response, success, status_code=None, err_message=""):
        self.status_code = status_code
        self.data = None

        if err_message:
            self.success = False
            self.error_message = err_message
            self.res_obj = {}
        else:
            self.success = success
            try:
                if isinstance(json_response, dict):
                    data_dict = json_response
                else:
                    data_dict = json.loads(json_response)
            except ValueError:
                raise APIException("APIResponse received a response which is not a valid JSON.", json_response)
            else:
                self.data = data_dict
                self.res_obj = {"status_code": self.status_code, "data": self.data}
                if not self.success:
                    try:
                        self.error_message = self.data["message"]
                    except KeyError:
                        raise APIException("Unexpected error format.", json_response)

    def as_dict(self):
        attribute_dict = {
            "res_obj": self.res_obj,
            "success": self.success,
            "status_code": self.status_code,
            "data": self.data
        }

        try:
            attribute_dict.update({"error_message": str(self.error_message)})
        except AttributeError:
            pass
        return attribute_dict

    def response(self):
        """
        The response we return as an HTTP response.
        Use instead of self.res_obj.
        """
        return {"status_code": self.status_code, "data": self.data}

    @classmethod
    def from_http_response(cls, http_response, err_message=""):
        """
        Generate APIResponse from http_response object

        :param http_response: input HTTP response object
        :param err_message: if there is an error message included, we include it in the APIResponse
        :return: The APIResponse object we generated
        """
        assert isinstance(http_response, HTTPResponse)
        return cls(http_response.read(), success=(http_response.status == 200), status_code=http_response.status,
                   err_message=err_message)

    def set_success_status(self, status):
        """
        This method sets the response success status

        :param status: input status
        """
        self.success = status
