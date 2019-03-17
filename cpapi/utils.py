import json
import sys


def compatible_loads(json_data):
    """
    Function json.loads in python 3.0 - 3.5 can't handle bytes, so this function handle it.
    :param json_data:
    :return: unicode (str if it's python 3)
    """
    if isinstance(json_data, bytes) and (3, 0) <= sys.version_info < (3, 6):
        json_data = json_data.decode("utf-8")
    return json.loads(json_data)
