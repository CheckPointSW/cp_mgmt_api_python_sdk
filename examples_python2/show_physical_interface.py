#
# show physical interface.py
# version 1.0
#
# The purpose of this script is to show a server's physical interfaces
#
# written by: Check Point software technologies inc.
# April 2019
#

# A package for reading passwords without displaying them on the console.
from __future__ import print_function

import getpass

import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# lib is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs


def main():
    # getting details from the user
    api_server = raw_input("Enter server IP address or hostname:")
    username = raw_input("Enter username: ")
    if sys.stdin.isatty():
        password = getpass.getpass("Enter password: ")
    else:
        print("Attention! Your password will be shown on the screen!")
        password = raw_input("Enter password: ")

    client_args = APIClientArgs(server=api_server, api_version="1", unsafe=True, context="gaia_api")

    with APIClient(client_args) as client:

        # login to server:
        login_res = client.login(username, password)

        if login_res.success is False:
            print("Login failed: {}".format(login_res.error_message))
            exit(1)
        interface_name = raw_input("Enter interface name: ")

        api_res = client.api_call("show-physical-interface", {
                "name": interface_name
        })
        if api_res.success:
            # in order to access any field within the data that had returned, simple use api_res.data["field name"]
            # or refer to the documentation page - https://<your-server-ip>/gaia_docs/
            print("Physical interface name is '{}' , ipv4 address is '{}', interface mtu is '{}'"
                  .format(api_res.data["name"], api_res.data["ipv4-address"], api_res.data["mtu"]))
        else:
            print("Failed to get physical interface data '{}'".format(api_res.data))


if __name__ == "__main__":
    main()
