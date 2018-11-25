"""
    tag2color.py
    version 1.1

    This script changes object colors based on a predefined tag2color_dictionary.
    The script asks the user to provide:
    1) Management Server IP
    2) Username
    3) Password
    4) Domain name or IP in the case of Multi-Domain environments
    5) Mode: "All" to go over all objects, or "Diff" to go over objects which were changed in a specific period.
    6) Start Time in the case of "Diff"-based coloring

    Before using the script,
    clone the Check Point Management API Python SDK and place it in the "lib" folder.

    written by: Check Point software technologies inc.
"""
from __future__ import print_function
import argparse
# A package for reading passwords without displaying them on the console.
import getpass
import sys
import os


# Before using the script,
# clone the Check Point Management API Python SDK and place it in the "lib" folder.
from lib import APIClient, APIClientArgs

from lib.tag2color_error import Tag2ColorError
from lib.api_command_formatter import APICommand, APIFormat


"""
    As a user, you can edit this dictionary with names of tags that you use in your organization and their matching colors.
"""
tag2color_dictionary = {"Internal": "Red", "DMZ": "Blue", "Finance": "Green", "external_gw": "Yellow"}


"""
    supported_types is an internal list of the Check Point objects that support setting their tags and colors using
    Management API.
"""
supported_types = [
    "host", "network", "group", "wildcard", "address-range",
    "multicast-address-range", "group-with-exclusion", "simple-gateway", "security-zone",
    "time", "time-group", "access-role", "dynamic-object", "dns-domain",
    "service-tcp", "service-udp", "service-icmp", "service-icmp6", "service-sctp",
    "service-other", "service-group", "application-site", "application-site-category",
    "application-site-group", "service-dce-rpc", "service-rpc",
    "vpn-community-meshed", "vpn-community-star"]
log_file = ""

# note: currently the Management API Python SDK ignores custom fingerprint paths so we have to use the default "fingerprints.txt"
FINGERPRINT_FILE = "fingerprints.txt"
API_CALLS_DEBUG_FILE = os.path.join("log", "api_calls.json")
LOG_FILE = os.path.join("log", "logfile.txt")


def color_object(obj_id, obj_name, obj_type, color):
    """
    Set the color of an existing object.
    :param obj_id: uid of the object that we should change its color
    :param obj_type: type of the object. This will help us call the correct API command.
    :param color: Color to set.
    :return: the API Command needed to set the color object. Later we can run it using the ApiClient
    or print it for the user to run it himself (for example to confirm a change by a SmartConsole Extension)
    """
    log("\n\tSetting the color for object '" + obj_name + "' of type '" + obj_type + "' to: " + color)
    return APICommand("set", obj_type, {"uid": obj_id, "color": color})


def get_desired_color(obj):
    """
    This method finds the correct color to set this object to based on its tag and type.
    :return: The color to change to, or None if a change isn't needed.
    """

    if "type" not in obj or obj["type"] is None or obj["type"] not in supported_types:
        return None

    color = None
    for tag in obj["tags"]:

        tag_name = tag["name"]
        log("\n\ttag is: " + tag_name)
        colorToSet = tag2color_dictionary[tag_name]
        if colorToSet and color is not None:
            log_and_throw("\n\tObject " + obj["name"] + " of type " + obj["type"] + " has more than one relevant tag.")
            return None

        color = colorToSet

    if obj["color"] == color:
        return None

    if color is not None:
        log("\n\t this is the color we want: " + color)
    return color


def color_all_tagged_objects(api_client):
    """
    This method searches for all objects that have one of the supported tags
    that appear in the "tag2color_dictionary" (see top of this file),
    then sets the correct color for each one of them.
    :param api_client: Api client of the domain
    :return: Number of changes that were made.
    """

    offset = 0
    total = 100

    # in order to fetch all objects with specific tags, we have to use the UID's of the tags, not the names of the tags.
    # so in the first step, we create a list of UID's that represent tags whose names appear as keys in tag2color_dictionary.
    tags_condition = []

    while offset < total:

        res = api_client.api_call("show-tags", {})
        if res.success is False:
            log_and_throw("Operation failed: {}. Aborting all changes.".format(res.error_message))

        total = res.data["total"]
        if not total:
            break

        start = res.data["from"]
        offset = res.data["to"]
        log("\n\tGoing over tags " + str(start) + " to " + str(offset) + " total " + str(total))

        for tag in res.data["objects"]:
            tag_name = tag["name"]
            tag_uid = tag["uid"]
            if tag_name in tag2color_dictionary:
                tags_condition.append(tag_uid)

    # optional: uncomment this if you want to validate that all the tags in tag2color_dictionary
    # actually exist in your security management server.
    # if len(tags_condition) != len(tag2color_dictionary):
    #    log_and_throw("The tag2color dictionary contains " + str(len(tag2color_dictionary)) +
    #                    " items, but the Security Management Server only found " + str(len(tags_condition)) + ".")
    log("\n\t No tags were found in the system - nothing to change.")
    return []

    # convert [tag_id1, tag_id2, tag_id3] to ["tags", tag_id1, "tags", tag_id2, "tags", tag_id3]
    tags_condition = [element for tag in tags_condition for element in ("tags", tag)]
    log("\n\tChecking all objects which have any of the tags " + ','.join(list(tag2color_dictionary)))

    offset = 0
    changes = []
    total = 100

    while offset < total:

        offset_suffix = "" if offset == 0 else " from offset " + str(offset) + " of total " + str(total)
        log("\n\tChecking all objects which have any of the tags " + ','.join(list(tag2color_dictionary)) + " " + offset_suffix)

        res = api_client.api_call("show-objects", {"in": tags_condition, "offset": offset, "details-level": "full"})

        if res.success is False:
            log_and_throw("Operation failed: {}. Aborting all changes.".format(res.error_message))

        total = res.data["total"]
        if not total:
            break

        start = res.data["from"]
        offset = res.data["to"]

        log("\n\tGoing over objects " + str(start) + " to " + str(offset) + " total " + str(total))
        for obj in res.data["objects"]:

            color = get_desired_color(obj)
            if color is None:
                continue

            changes.append(color_object(obj["uid"], obj["name"], obj["type"], color))

        log("\n\t" + str(len(changes)) + " total changes so far.")

    return changes


def color_all_changed_objects(api_client, start_time):
    """
    This method searches for all objects that were changed in a given time period,
    and for each changed object whose tag in one of the tags
    defined in the "tag2color_dictionary" (see top of this file),
    it sets the color accordingly.
    :param api_client: APi client of the domain
    :param start_time: start time to check changes from
    :return: Number of changed objects
    """
    if not start_time:
        log_and_throw("When running tag2color in diff mode, start-time parameter is required.")

    changes = []
    offset = 0
    total = 100

    while offset < total:

        offset_suffix = "" if offset == 0 else " from offset " + str(offset) + " of total " + str(total)
        log("\n\tChecking all changed objects since " + start_time + " " + offset_suffix)

        res = api_client.api_call("show-changes", {"from-date": start_time, "offset": offset, "details-level": "full"})

        if res.success is False:
            log_and_throw("Operation failed: {}. Aborting all changes.".format(res.error_message))

        # the show-changes API command returns an array with one task that has an array with one "task-details".
        # this task-details has list of "operations".
        # each "operation" has dictionaries for added-objects, modified-objects and deleted-objects.
        # we are interested with the added-objects and modified-objects.
        if not res.data:
            break

        if (not res.data["tasks"]) or len(res.data["tasks"]) > 1:
            log_and_throw("Expected 1 task, got: " +
                          ("no tasks" if not res.data["tasks"] else len(res.data["tasks"])))

        task = res.data["tasks"][0]
        if (not task["task-details"]) or len(task["task-details"]) > 1:
            log_and_throw("Expected 1 task-details element, got: " +
                          ("no tasks" if not task["task-details"]else len(task["task-details"])))

        task_details = task["task-details"][0]
        total = task_details["total"]

        if not total:
            break

        start = task_details["from"]
        offset = task_details["to"]

        log("\n\tGoing over objects " + str(start) + " to " + str(offset) + " total " + str(total))

        change_containers = [operation_changes["operations"] for operation_changes in task_details["changes"]]
        added_objects = [added_object for change in change_containers for added_object in change["added-objects"]]
        modified_objects = [modified_object for change in change_containers for modified_object in change["modified-objects"]]

        log("\n\tNumber of added objects: " + str(len(added_objects)))
        log("\n\tNumber of modified objects: " + str(len(modified_objects)))
        for added_object in added_objects:

            color = get_desired_color(added_object)
            if color is None:
                continue

            changes.append(color_object(added_object["uid"], added_object["name"], added_object["type"], color))

        for modified_object in modified_objects:

            new_object = modified_object["new-object"]
            color = get_desired_color(new_object)
            if color is None:
                continue

            changes.append(color_object(new_object["uid"], new_object["name"], new_object["type"], color))

    log("\n\t" + str(len(changes)) + " total changes so far.")

    return changes


def log(message):
    """
    This method writes message to the log file and print it
    :param message: message that will be written to log file
    """
    global log_file
    print(message, file=log_file)
    print(message)


def log_and_throw(message):
    log(message)
    raise Tag2ColorError(message)


def init_log_files(api_client):
    # Creates debug file. The debug file contains all the communication
    # between the python script and Check Point's management server.
    api_client.debug_file = API_CALLS_DEBUG_FILE

    global log_file
    log_file = open(LOG_FILE, 'w+')


def close_log_files():
    log_file.close()


def validate_api_server_version(api_version):
    if not api_version or api_version == "1.0" or api_version == "1":
        log_and_throw("API version 1.0 is not supported for tag2color since it does not contain the show-changes command.")


def run_tag2color(api_client, mode, start_time):

    if mode == "changed-objects":
        return color_all_changed_objects(api_client, start_time)
    elif mode == "all-objects":
        return color_all_tagged_objects(api_client)
    else:
        log_and_throw("Valid values for mode are all or diff.")


def tag2color_authenticated(api_context, mode, start_time):

    api_version = api_context["data"]["api-server-version"]
    validate_api_server_version(api_version)
    api_server = api_context["data"]["server"]
    with APIClient(APIClientArgs(server=api_server)) as client:

        init_log_files(client)
        client.save_fingerprint_to_file(api_server, api_context["data"]["server-fingerprint"], FINGERPRINT_FILE)
        client.set_login_response(
            api_context["data"]["sid"],
            api_context["data"]["domain"],
            api_version)

        return run_tag2color(client, mode, start_time)


def tag2color(username, password, server, domain, mode, start_time):

    if not username or not password or not server or not mode:
        raise Tag2ColorError("Username, password, server IP or hostname, and mode are required.")

    with APIClient(APIClientArgs(server=server)) as client:

        init_log_files(client)
        client.fingerprint_filename = FINGERPRINT_FILE

        # The API client, would look for the server's certificate SHA1 fingerprint
        # in a file.
        # If the fingerprint is not found on the file, it will ask the user if he
        # accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            log_and_throw("Could not get the server's fingerprint - Check connectivity with the server.")

        # login to server
        login_res = client.login(username, password, domain=domain)
        if login_res.success is False:
            log_and_throw("Login failed: {}".format(login_res.error_message))
        validate_api_server_version(login_res.data["api-server-version"])

        try:
            changes = run_tag2color(client, mode, start_time)
            if len(changes) > 0:

                for change in changes:
                    client.api_call(change.format_command_and_verb(APIFormat.WEB_SERVICE), change.parameters)

                # publish changes
                log("\n\tPublishing " + str(len(changes)) + " changes.")
                res = client.api_call("set-session", {"new-name": "tag2color", "description": "Changing colors of objects based on tags"})
                if res.success is False:
                    log_and_throw("Failed to set the current session: {}".format(res.error_message))

                res = client.api_call("publish", {})
                if res.success is False:
                    log_and_throw("Publish failed: {}".format(res.error_message))

        except Exception as e:
            res = client.api_call("discard", {})
            if res.success is False:
                message = "Discard failed: {}".format(res.error_message)
                log(message)
            close_log_files()
            raise Tag2ColorError(e.message)

        if not changes:
            log("\n\tNo changes were made. Logging out.")
            res = client.api_call("logout", {})
            if res.success is False:
                message = "Logout failed: {}".format(res.error_message)
                log(message)
                close_log_files()
                raise Tag2ColorError(message)

        # close the log file
        close_log_files()


def main(argv):
    # Initialize arguments
    if argv:
        parser = argparse.ArgumentParser()
        parser.add_argument("-m", "--management", required=False, default=os.getenv('MGMT_CLI_MANAGEMENT', "127.0.0.1"),
                            help="The management server's IP address (In the case of a Multi-Domain Environment, \
                            use the IP address of the MDS domain).\nDefault: 127.0.0.1\n\
                            Environment variable: MGMT_CLI_MANAGEMENT")
        parser.add_argument("-u", "--username", required=False, default=os.getenv('MGMT_CLI_USER'),
                            help="The management administrator's user name.\nEnvironment variable: MGMT_CLI_USER")
        parser.add_argument("-p", "--password", required=False,
                            help="The management administrator's password.\nEnvironment variable: MGMT_CLI_PASSWORD")
        parser.add_argument("-d", "--domain", required=False, default=os.getenv('MGMT_CLI_DOMAIN'),
                            help="The name, uid or IP-address of the management domain\n\
                            Environment variable: MGMT_CLI_DOMAIN")
        parser.add_argument("-s", "--strategy", type=str, action="store", help="The mode in which coloring objects should be: all-objects or changed-objects", dest="strategy", default="all")
        parser.add_argument("-t", "--start-time", type=str, action="store", help="Start Time in case mode is changed-objects, in ISO 8691 format, example: 2017-02-01T08:20:50:", dest="start_time", default="")

        args = parser.parse_args()

        required = "management username password".split()

        for r in required:
            if args.__dict__[r] is None:
                parser.error("parameter '%s' required" % r)

        management = args.management
        username = args.username
        password = args.password
        domain = args.domain
        mode = args.strategy
        start_time = args.start_time

    else:
        management = raw_input("Enter server IP address or hostname: ")
        username = raw_input("Enter username: ")
        if sys.stdin.isatty():
            password = getpass.getpass("Enter password: ")
        else:
            print("Attention! Your password will be shown on the screen!")
            password = raw_input("Enter password: ")

        domain = raw_input("Enter domain IP or name or Enter if this is a Security Management Server: ")
        mode = raw_input("Enter mode: \"all-objects\" or \"changed-objects\": ")
        start_time = ""
    if mode == "changed-objects" and start_time is None:
            start_time = raw_input("Enter start time for diff in ISO 8601 format, example: 2017-02-01T08:20:50: ")

    tag2color(username, password, management, domain, mode, start_time)


if __name__ == "__main__":
    main(sys.argv[1:])
