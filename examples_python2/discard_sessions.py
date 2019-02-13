#
# discardSessions.py
# version 1.0
#
# The purpose of this script is to unlock objects, which were locked by another session of this user.
# The sessions will be unlocked by discarding changes which were done during that session.
# Only those sessions will be discarded which belong to the user and were created via Web APIs or CLI.
#
# written by: Check Point software technologies inc. 
# July 2016
#

# A package for reading passwords without displaying them on the console.
from __future__ import print_function

import getpass

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# cpapi is a library that handles the communication with the Check Point management server.
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

    client_args = APIClientArgs(server=api_server)

    with APIClient(client_args) as client:

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

        show_sessions_res = client.api_query("show-sessions", "full")

        if not show_sessions_res.success:
            print("Failed to retrieve the sessions")
            return

        for sessionObj in show_sessions_res.data:
            # Ignore sessions that were not created with WEB APIs or CLI
            if sessionObj["application"] != "WEB_API":
                continue

            discard_res = client.api_call("discard", {"uid": sessionObj['uid']})
            if discard_res.success:
                print("Session '{}' discarded successfully".format(sessionObj['uid']))
            else:
                print("Session '{}' failed to discard".format(sessionObj['uid']))


if __name__ == "__main__":
    main()
