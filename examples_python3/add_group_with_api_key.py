#
# add_group_with_api_key.py
# version 1.0
#
#
# This example demonstrates communication with Check Point Management server using Management API Library in Python.
# Login with api-key, and adding a group.
# The demonstrated commands are:
#
#   1. login with api-key
#   2. adding a group
#   3. publishing the changes
#
# Logout command is called automatically after the work with Management API Library is completed.
#

from __future__ import print_function

# A package for reading passwords without displaying them on the console.
import getpass

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs


def main():
    # getting details from the user
    api_server = input("Enter server IP address or hostname:")

    if sys.stdin.isatty():
        api_key = getpass.getpass("Enter api-key: ")
    else:
        print("Attention! Your api-key will be shown on the screen!")
        api_key = input("Enter api-key: ")

    client_args = APIClientArgs(server=api_server)

    with APIClient(client_args) as client:

        group_name = input("Enter the name of the group: ")

        #
        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        # login to server:
        login_res = client.login_with_api_key(api_key)

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)

        # add the group
        add_group_response = client.api_call("add-group",
                                            {"name": group_name})

        if add_group_response.success:

            print("The group: '{}' has been added successfully".format(group_name))

            # publish the result
            publish_res = client.api_call("publish", {})
            if publish_res.success:
                print("The changes were published successfully.")
            else:
                print("Failed to publish the changes.")
        else:
            print("Failed to add the group: '{}', Error:\n{}".format(group_name, add_group_response.error_message))


if __name__ == "__main__":
    main()
