#
# addAccessRule.py
# version 1.0
#
#
# This example demonstrates communication with Check Point Management server using Management API Library in Python.
# The demonstrated commands are:
#
#   1. login
#   2. adding an access rule to the top of Network layer
#   3. publishing the changes
#
# Logout command is called automatically after the work with Management API Library is completed.
#
# written by: Check Point software technologies inc. 
# July 2016
#

from __future__ import print_function

# A package for reading passwords without displaying them on the console.
import getpass

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# lib is a library that handles the communication with the Check Point management server.
from lib import APIClient, APIClientArgs


def main():
    # getting details from the user
    api_server = raw_input("Enter server IP address or hostname:")
    username = raw_input("Enter username: ")
    if sys.stdin.isatty():
        password = getpass.getpass("Enter password: ")
    else:
        print("Attention! Your password will be shown on the screen!")
        password = raw_input("Enter password: ")

    client_args = APIClientArgs(server=api_server)

    with APIClient(client_args) as client:

        rule_name = raw_input("Enter the name of the access rule: ")

        #
        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        # login to server:
        login_res = client.login(username, password)

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)

        # add a rule to the top of the "Network" layer
        add_rule_response = client.api_call("add-access-rule",
                                            {"name": rule_name, "layer": "Network", "position": "top"})

        if add_rule_response.success:

            print("The rule: '{}' has been added successfully".format(rule_name))

            # publish the result
            publish_res = client.api_call("publish", {})
            if publish_res.success:
                print("The changes were published successfully.")
            else:
                print("Failed to publish the changes.")
        else:
            print("Failed to add the access-rule: '{}', Error:\n{}".format(rule_name, add_rule_response.error_message))


if __name__ == "__main__":
    main()
