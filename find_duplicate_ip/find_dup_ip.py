#
# findDupIP.py
# version 1.0
#
#
# Look for duplicate IP addresses in all the host objects.
# written by: Check Point software technologies inc. 
# December 2015
#


# A package for reading passwords without displaying them on the console.
from __future__ import print_function

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

        # create debug file. The debug file will hold all the communication between the python script and
        # Check Point's management server.
        client.debug_file = "api_calls.json"

        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        # login to server:
        login_res = client.login(username, password)

        if login_res.success is False:
            print("Login failed: {}".format(login_res.error_message))
            exit(1)

        # show hosts
        show_hosts_res = client.api_query("show-hosts", "full")
        if show_hosts_res.success is False:
            print("Failed to get the list of all host objects: {}".format(show_hosts_res.error_message))
            exit(1)

    # obj_dictionary - for a given IP address, get an array of hosts (name, unique-ID) that use this IP address.
    obj_dictionary = {}

    # dup_ip_set - a collection of the duplicate IP addresses in all the host objects.
    dup_ip_set = set()

    for host in show_hosts_res.data:
        ipaddr = host["ipv4-address"]
        host_data = {"name": host["name"], "uid": host["uid"]}
        if ipaddr in obj_dictionary:
            dup_ip_set.add(ipaddr)
            obj_dictionary[ipaddr] += [host_data]  # '+=' modifies the list in place
        else:
            obj_dictionary[ipaddr] = [host_data]

    # print list of duplicate IP addresses to the console
    print("\n")
    print("List of Duplicate IP addresses: ")
    print("------------------------------- \n")

    if len(dup_ip_set) == 0:
        print("No hosts with duplicate IP addresses")

    # for every duplicate ip - print hosts with that ip:
    for dup_ip in dup_ip_set:
        print("\nIP Address: " + dup_ip + "")
        print("----------------------------------")

        for obj in obj_dictionary[dup_ip]:
            print(obj["name"] + " (" + obj["uid"] + ")")


if __name__ == "__main__":
    main()
