import sys
if sys.version_info >= (3, 0):
    from . import mgmt_api
    from . import api_exceptions
else:
    from mgmt_api import APIClient
    from mgmt_api import APIClientArgs
    from api_exceptions import APIException
    from api_exceptions import APIClientException
