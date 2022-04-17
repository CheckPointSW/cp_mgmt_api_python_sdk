from __future__ import print_function

# A package for reading passwords without displaying them on the console.
import argparse
import getpass

import sys, os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs, APIResponse


def main(usera="python-api-wrapper"):

    client_args = APIClientArgs(server="172.23.3.10", port=443, user_agent=usera)

    with APIClient(client_args) as client:

        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        # login to server:
        login_res = client.login_as_root()

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)
        else:
            print("Logged in kululu")
        start = time.time()
        res = client.api_call("show-session")
        end = time.time() - start
        if res.success is True:

            print("The script has been executed successfully in "+ str(end)+"seconds")

            # publish the result
            publish_res = client.api_call("publish", {})
            if publish_res.success:
                for call in client_args.api_calls:
                    print(call)
            else:
                print("Failed to publish the changes.")
        else:
            print("Failed to run:  Error:\n{}".format(res.error_message))


if __name__ == "__main__":
    if len(sys.argv)>1:
        usera = sys.argv[1]
        main(usera)
    else:
        main()
