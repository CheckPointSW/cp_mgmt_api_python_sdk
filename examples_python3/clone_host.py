"""
    clone_host.py
    version 1.1

    This script creates a new host object and adds it to all groups and rules to which an existing host object belongs to.
    The script asks the user to provide:
    1) Management Server IP
    2) Username
    3) Password
    4) The IP of the existing host object
    5) A name for the new host object that will be created
    6) An IP-address for the new host-object
    7) Global domain name
    8) Auto assign flag

    written by: Check Point software technologies inc.
"""
from __future__ import print_function

import argparse
# A package for reading passwords without displaying them on the console.
import getpass

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# lib is a library that handles the communication with the Check Point management server.
from lib.mgmt_api import APIClient, APIClientArgs

global_domain_cloned_host_uid = None
log_file = ""


def create_host(api_client, orig_host_name, orig_host_uid, cloned_host_name, cloned_host_ip):
    """
    Create a new host object with 'new_host_name' as its name and 'new_host_ip_address' as its IP-address.
    The new host's color and comments will be copied from the the "orig_host" object.
    :param api_client: Api client of the domain
    :param orig_host_uid: original host uid
    :param cloned_host_name: cloned host name
    :param cloned_host_ip: cloned host IP
    :return: the cloned host uid on success, otherwise None
    """
    # get details of the original host object
    log("\n\tGathering information for host {}".format(orig_host_name))
    res = api_client.api_call("show-host", {"uid": orig_host_uid})
    if res.success is False:
        discard_write_to_log_file(api_client, "Failed to open existing host: {}. Aborting.".format(res.error_message))
        return None

    # copy the color and comments from the original host
    color = res.data["color"]
    comments = res.data["comments"]

    # create a new host object
    log("\n\tCreating a new host {}".format(cloned_host_name))
    res = api_client.api_call("add-host", {"name": cloned_host_name, "ip-address": cloned_host_ip,
                                           "color": color, "comments": comments})
    if res.success is False:
        discard_write_to_log_file(api_client, "Failed to create the new host: {}. Aborting.".format(res.error_message))
        return None

    return res.data["uid"]


def find_host_uid_if_exist(api_client, cloned_host_name, cloned_host_ip):
    """
    This method checks if the new host already exists, and if so the method returns the tuple uid and status
    :param api_client: Api client of the domain
    :param cloned_host_name: cloned host name
    :param cloned_host_ip: cloned host IP
    :return: True if the host doesn't exist
             False if error occurred
             UID if the host already exists, and the uid is the same uid of the existing host
    """
    # check if the host already exists, find the host uid
    res = api_client.api_call("show-host", {"name": cloned_host_name})
    if res.success is False:
        if "code" in res.data and "generic_err_object_not_found" == res.data["code"]:
            return True
        else:
            discard_write_to_log_file(api_client,
                                      "Operation failed: {}. Aborting all changes.".format(res.error_message))
            return False

    if res.data["ipv4-address"] == cloned_host_ip:
        log("\n\tThe host with the same name and IP already exists,\n\t"
            "going to copy it to the same places as the original host")
        return res.data["uid"]
    else:
        discard_write_to_log_file(api_client, "A host with the same name but a different IP address "
                                              "already exists, discarding all changes")
        return False


def copy_reference(api_client, new_host_uid, new_host_name, where_used_data, is_global_domain):
    """
    Add new_host to the same groups, access-rules, NAT-rules, and threat-rules that orig_host belongs to
    :param api_client: APi client of the domain
    :param new_host_uid: cloned host uid
    :param new_host_name: cloned host name
    :param where_used_data: the data returned from where-used for the original host
    :param is_global_domain: True if the domain is global
    :return: True on success, otherwise False
    """
    log("\n\tAdding '" + new_host_name + "' to:")

    # handle group objects
    if where_used_data["objects"]:
        for obj in where_used_data["objects"]:
            if obj["type"] == "group":
                # in case we connect to local domain and the group is a global group, skip
                if not is_global_domain and obj["domain"]["domain-type"] == "global domain":
                    continue
                log("\t\tGroup: " + obj["name"])
                res = api_client.api_call("set-group", {"name": obj["name"], "members": {"add": new_host_uid}})
                if res.success is False:
                    discard_write_to_log_file(api_client, "Adding the new host to the group failed. Error: "
                                                          "{}. Aborting all changes.".format(res.error_message))
                    return False

    # handle access-rules
    if where_used_data["access-control-rules"]:
        for obj in where_used_data["access-control-rules"]:
            # in case we connect to a local admin and the layer is a global layer, skip
            if not is_global_domain and obj["rule"]["domain"]["domain-type"] == "global domain":
                continue
            if set_access_rule(api_client, obj, new_host_uid) is False:
                return False

    # handle nat-rules
    if where_used_data["nat-rules"]:
        for obj in where_used_data["nat-rules"]:
            if set_nat_rule(api_client, obj, new_host_uid) is False:
                return False

    # handle threat-rules
    if where_used_data["threat-prevention-rules"]:
        for obj in where_used_data["threat-prevention-rules"]:
            # in case we connect to a local admin and the layer is a global layer, skip
            if not is_global_domain and obj["rule"]["domain"]["domain-type"] == "global domain":
                continue
            if set_threat_rule(api_client, obj, new_host_uid) is False:
                return False

    # we're done. call 'publish'
    res = api_client.api_call("publish", {})
    if res.success is False:
        discard_write_to_log_file(api_client,
                                  "Publish failed. Error: {}. Aborting all changes.".format(res.error_message))
        return False

    return True


def set_threat_rule(api_client, obj, new_host_uid):
    """
    This method sets the given threat rule according to the places where the original host appears
    :param api_client: Api client of the domain
    :param obj: the access rule object
    :param new_host_uid: new host uid
    :return: True on success, otherwise False
    """
    command = "set-threat-rule"

    payload = {"uid": obj["rule"]["uid"], "layer": obj["layer"]["uid"]}
    if obj["rule"]["type"] == "threat-exception":
        command = "set-threat-exception"
        payload = {"uid": obj["rule"]["uid"], "exception-group-uid": obj["layer"]["uid"]}

    if "package" in obj:
        log("\t\tRule number {} in policy {} (layer: {})".format(obj["position"], obj["package"]["name"],
                                                                 obj["layer"]["name"]))
    else:
        log("\t\tRule number {} (layer: {})".format(obj["position"], obj["layer"]["name"]))

    need_to_set_rule = False

    for column in obj["rule-columns"]:
        if column == "source":
            payload.update({"source": {"add": new_host_uid}})
            need_to_set_rule = True
        if column == "destination":
            payload.update({"destination": {"add": new_host_uid}})
            need_to_set_rule = True
        if column == "scope":
            payload.update({"protected-scope": {"add": new_host_uid}})
            need_to_set_rule = True

    if need_to_set_rule:
        res = api_client.api_call(command, payload)
        if res.success is False:
            discard_write_to_log_file(api_client,
                                      "Adding new host to threat rule failed."
                                      " Error: {}. Aborting all changes.".format(res.error_message))
            return False

    return True


def set_nat_rule(api_client, obj, new_host_uid):
    """
    This method creates a new rule identical to the given rule, and puts the new host at the same places as
    the original host
    :param api_client: Api client of the domain
    :param obj: nat layer object
    :param new_host_uid: new host uid
    :return: True on success, False in error
    """
    # get rule details
    rule_info = api_client.api_call("show-nat-rule", {"uid": obj["rule"]["uid"], "package": obj["package"]["uid"],
                                                      "details-level": "uid"})
    if rule_info.success is False:
        discard_write_to_log_file(api_client, "Failed to get rule details")
        return False

    log("\t\tCreate new nat rule in policy {} below rule: {}".format(obj["package"]["name"], obj["rule"]["uid"]))
    rule_data = rule_info.data

    # add new nat rule as the existing one
    res = api_client.api_call("add-nat-rule", {"package": obj["package"]["name"],
                                               "position": {"below": obj["rule"]["uid"]},
                                               "enabled": rule_data["enabled"],
                                               "install-on": rule_data["install-on"],
                                               "method": rule_data["method"],
                                               "original-destination": rule_data["original-destination"],
                                               "original-service": rule_data["original-service"],
                                               "original-source": rule_data["original-source"],
                                               "translated-destination": rule_data["translated-destination"],
                                               "translated-service": rule_data["translated-service"],
                                               "translated-source": rule_data["translated-source"]})
    if res.success is False:
        discard_write_to_log_file(api_client, "Adding new nat rule failed."
                                              " Error: {}. Aborting all changes.".format(res.error_message))
        return False

    payload = {"package": obj["package"]["uid"], "uid": res.data["uid"]}
    need_to_set_rule = False

    # set the nat rule according the place the original host is appear
    for column in obj["rule-columns"]:
        if column == "original-source":
            payload.update({"original-source": new_host_uid})
            need_to_set_rule = True
        if column == "original-destination":
            payload.update({"original-destination": new_host_uid})
            need_to_set_rule = True
        if column == "translated-source":
            payload.update({"translated-source": new_host_uid})
            need_to_set_rule = True
        if column == "translated-destination":
            payload.update({"translated-destination": new_host_uid})
            need_to_set_rule = True

    if need_to_set_rule:
        res = api_client.api_call("set-nat-rule", payload)
        if res.success is False:
            discard_write_to_log_file(api_client,
                                      "Adding new host to nat rule failed. "
                                      "Error: {}. Aborting all changes.".format(res.error_message))
            return False

    return True


def set_access_rule(api_client, obj, new_host_uid):
    """
    This method sets the given access rule according to places the original host appears
    :param api_client: Api client of the domain
    :param obj: the access rule object
    :param new_host_uid: new host uid
    :return: True on success, otherwise False
    """
    if "package" in obj:
        log("\t\tRule number {} in policy {} (layer: {})".format(obj["position"], obj["package"]["name"],
                                                                 obj["layer"]["name"]))
    else:
        log("\t\tRule number {} (layer: {})".format(obj["position"], obj["layer"]["name"]))

    payload = {"uid": obj["rule"]["uid"], "layer": obj["layer"]["uid"]}
    need_to_set_rule = False

    # finds if the rule appears in the source or destination
    for column in obj["rule-columns"]:
        if column == "source":
            payload.update({"source": {"add": new_host_uid}})
            need_to_set_rule = True
        if column == "destination":
            payload.update({"destination": {"add": new_host_uid}})
            need_to_set_rule = True

    if need_to_set_rule:
        res = api_client.api_call("set-access-rule", payload)
        if res.success is False:
            discard_write_to_log_file(api_client,
                                      "Adding new host to access rule failed."
                                      " Error: {}. Aborting all changes.".format(res.error_message))
            return False

    return True


def print_unsupported_objects(orig_host_name, where_used_data, is_global_domain):
    """
     This function is for logging purposes only.
     It prints a list of unsupported references that the original host belongs to.
     Go over all the different references that the whereu sed API is pointing to.
     If the reference is not a group, report it as an unsupported type.
    :param orig_host_name: original host name
    :param where_used_data: the data returned from where-used command on the original host
    :param is_global_domain: True if the domain there where-used run was the global domain
    :return: True if there are unsupported reference
    """
    has_unsupported_reference = False

    # go over all the objects
    if where_used_data["objects"]:
        for obj in where_used_data["objects"]:
            # Report all the objects that their type is not 'group'.
            # We don't report the objects which belong to the global domain, if the login was done to a
            # local domain, because such an object was reported when the global domain was handled.
            if obj["type"] != "group" and (
                    is_global_domain or obj["domain"]["domain-type"] != "global domain"):
                has_unsupported_reference = True
                log("n\t'{}' is referenced by '{}', Type: '{}'".format(orig_host_name, obj["name"], obj["type"]))

    return has_unsupported_reference


def is_global_host_in_local_domain(api_client, domain_name):
    """
    This method checks if the global host is in the local domain.
    :param domain_name: domain name
    :param api_client: Api client of the local domain
    :return: True if the global host exists on the local domain, False if the host does not exist,
     None if the error occurred
    """
    global global_domain_cloned_host_uid

    # the global host string is empty, the global host wasn't created
    if global_domain_cloned_host_uid is None:
        log("\n\tThe new global host wasn't created. There is noting to do for this original host")
        return False

    # check if the global domain exits in the local domain (assign was carried out)
    res = api_client.api_call("show-host", {"uid": global_domain_cloned_host_uid})
    if res.success is False:
        # check if the global host doesn't appear on the local domain
        if "code" in res.data and "generic_err_object_not_found" == res.data["code"]:
            log("\n\tThe new host (uid: " + global_domain_cloned_host_uid + ") does not appear in the local domain: "
                + domain_name + ".")
            log("\tIn order to put the cloned host to the same places as the original one, call assign-global-assignment"
                " domain and then run the script again.\n")
            return False
        else:
            # error occurred
            discard_write_to_log_file(api_client, "\n\tFailed to get global host with uid: "
                                      + global_domain_cloned_host_uid)
            return None

    # global host is in the local domain
    return True


def find_host_by_ip_and_clone(api_client, orig_host_ip, cloned_host_name, cloned_host_ip, is_global_domain=True,
                              domain_name=""):
    """
    This method finds the host uid which has IP address as the given host, and clones this host.
    :param api_client: Api client of the domain
    :param cloned_host_ip: cloned host IP
    :param cloned_host_name: cloned host name
    :param orig_host_ip: original host ip
    :param is_global_domain: True if the domain is global
    :param domain_name: domain name
    :return: True on success, otherwise False
    """
    hosts = api_client.api_query("show-hosts", details_level="full")
    if hosts.success is False:
        discard_write_to_log_file(api_client, "Failed to get show-host data: {}".format(hosts.error_message))
        return False

    # go over all the exist hosts and look for host with same ip as orig_host
    for host_object in hosts.data:
        # if the ip is not as the original host continue looking
        if host_object["ipv4-address"] != orig_host_ip:
            continue

        # found host with the same ip as orig_host, get the data of the host
        orig_host_name = host_object["name"]
        orig_host_uid = host_object["uid"]
        log("\n\tFound host name: " + orig_host_name + ", with IP: " + orig_host_ip + " and UID: " + orig_host_uid)

        # check if the host belongs to global or local domain
        global_host = False
        if host_object["domain"]["domain-type"] == "global domain":
            global_host = True

        # if login was done to a local domain and the host with the given IP is global, check if the new
        # host exists (assign global policy had been already done)
        if not is_global_domain and global_host:
            log("\n\tThe original host belongs to the global domain")
            # Verify that assign-global-policy was done
            is_appear = is_global_host_in_local_domain(api_client, domain_name)
            # error occurred
            if is_appear is None:
                return False
            # can't find global host in the local domain, assign-global-policy was not done
            elif is_appear is False:
                continue

        if check_if_the_host_exist_and_send_to_preform_clone(api_client, orig_host_name, orig_host_uid,
                                                             cloned_host_name, cloned_host_ip, is_global_domain,
                                                             global_host) is False:
            return False

    return True


def check_if_the_host_exist_and_send_to_preform_clone(api_client, orig_host_name, orig_host_uid, cloned_host_name,
                                                      cloned_host_ip, is_global_domain, is_global_host):
    """
    This method looks for the places in which the host that needs to be cloned appears,
    creates a new host and adds it to all the relevant places.
    The new host is created only if it has not been created yet, though this new host is still added to all the
    places where the original host appears.
    :param api_client: Api client of the domain
    :param orig_host_name: original host name
    :param orig_host_uid: original host uid
    :param cloned_host_name: cloned host name
    :param cloned_host_ip: cloned host ip
    :param is_global_domain: True if the the domain is global
    :param is_global_host: True if the host is belong to the global domain
    :return: True on success, otherwise False
    """
    global global_domain_cloned_host_uid

    if not is_global_domain and is_global_host:
        log("\tCopy the global host to relevant references")
        cloned_host_uid = global_domain_cloned_host_uid
    else:
        host_uid = find_host_uid_if_exist(api_client, cloned_host_name, cloned_host_ip)
        # error occurred while executing "show-host"
        if host_uid is False:
            return False

        # the host doesn't exist
        if host_uid is True:
            new_host = create_host(api_client, orig_host_name, orig_host_uid, cloned_host_name, cloned_host_ip)
            # error occurred
            if new_host is None:
                return False
            # succeeded create host
            else:
                cloned_host_uid = new_host
        # the host already exist
        else:
            cloned_host_uid = host_uid

        # if the domain is global save the uid of the new host
        if is_global_domain:
            global_domain_cloned_host_uid = cloned_host_uid

    clone_res = perform_cloning(api_client, orig_host_name, orig_host_uid, cloned_host_name,
                                is_global_domain, cloned_host_uid)
    if clone_res is False and is_global_domain:
        global_domain_cloned_host_uid = None

    return clone_res


def perform_cloning(api_client, orig_host_name, orig_host_uid, cloned_host_name, is_global_domain, new_host_uid):
    """
    This method copies the given host to the places where the original host appears.
    :param api_client: Api client of the domain
    :param orig_host_name: original host name
    :param orig_host_uid: original host uid
    :param cloned_host_name: cloned host name
    :param is_global_domain: True if the domain is global
    :param new_host_uid: new host uid, if exist
    :return: True on success, otherwise False
    """
    where_used = where_host_used(api_client, orig_host_name, orig_host_uid)
    if where_used is False or where_used is True:
        return where_used

    # print all unsupported references (i.e. references that will not be copied to the new object)
    has_unsupported_reference = print_unsupported_objects(orig_host_name,
                                                          where_used.data["used-directly"], is_global_domain)

    # if there are unsupported references, ask the user what to do:
    if has_unsupported_reference:
        answer = input("\n\tThe new host '{}' will not be copied to the list of reference(s) "
                       "shown above!\n\tContinue anyway? [y/n]".format(cloned_host_name))
        if not answer.lower() == "y":
            return True

    return copy_reference(api_client, new_host_uid, cloned_host_name, where_used.data["used-directly"],
                          is_global_domain)


def where_host_used(api_client, orig_host_name, orig_host_uid):
    """
    This method executes 'where-used' command on a given host and returns the command response on success.
    If the original host is not used by any object, the method returns True.
    In case of an error, the method returns False.
    :param api_client: Api client of the domain
    :param orig_host_name: original host name
    :param orig_host_uid: original host uid
    :return: the places the host is used, True if the host is not used, False in case of an error
    """
    # call the where-used API for the object we need to clone
    where_used = api_client.api_call("where-used", {"uid": orig_host_uid})
    if where_used.success is False:
        discard_write_to_log_file(api_client,
                                  "Failed to get " + orig_host_name + " data: {}".format(where_used.error_message))
        return False

    # if the object is not being referenced there is nothing to do.
    if where_used.data["used-directly"]["total"] == 0:
        log("\t" + orig_host_name + " is not used! -- nothing to do")
        return True

    return where_used


def handle_local_domain(client_domain, domain, username, password, orig_host_ip, cloned_host_name,
                        cloned_host_ip):
    """
    This method login to a given local domain and looks for the host need to be clone, if the host exist clone it.
    Then log out the domain.
    :param client_domain: Api client of the domain
    :param domain: domain name
    :param username: user name
    :param password: password
    :param orig_host_ip: original host IP
    :param cloned_host_name: cloned host name
    :param cloned_host_ip: cloned host IP
    """
    connect_message = "Connecting to domain: " + domain["name"]
    log("\n" + connect_message)
    log('-' * len(connect_message))

    # login to server domain:
    login_res = client_domain.login(username, password, domain=domain["name"])
    if login_res.success is False:
        log("Login failed: {}".format(login_res.error_message))
        return

    try:
        # clone the given host on the domain server
        find_host_by_ip_and_clone(client_domain, orig_host_ip, cloned_host_name, cloned_host_ip, is_global_domain=False,
                                  domain_name=domain["name"])
    finally:
        # logout global domain server
        client_domain.api_call("logout", {})


def handle_global_domain(client, user_name, password, client_domain, global_domain_name, is_auto_assign,
                         orig_host_ip, cloned_host_name, cloned_host_ip):
    """
    This method performs login to a global domain and looks for the host which is needed to be cloned.
    If the host is found in the domain, clone it and assign the changes on the local domains.
    The policy assignment is done only if the auto assign is turned on.
    At the end, log out from the domain
    :param client: Api client of the MDS
    :param user_name: user name
    :param password: password
    :param client_domain: Api client of the local domain
    :param global_domain_name: global domain name
    :param is_auto_assign: True if the user agree to do auto assign
    :param orig_host_ip: original host IP
    :param cloned_host_name: cloned host name
    :param cloned_host_ip: cloned host IP
    """
    # login to the global domain
    login_res = client_domain.login(user_name, password, domain=global_domain_name)
    if login_res.success is False:
        log("Login to the global domain: " + global_domain_name +
            " failed: {}. The host will not be cloned in the global domain".format(login_res.error_message))
        return

    connect_message = "Connecting to domain: " + global_domain_name
    log("\n" + connect_message)
    log('-' * len(connect_message))

    try:
        # clone the given host on the domain server
        # The way to know whether a policy package in the client_domain was changed
        find_host_res = find_host_by_ip_and_clone(client_domain, orig_host_ip, cloned_host_name, cloned_host_ip,
                                                  is_global_domain=True, domain_name=global_domain_name)
    finally:
        # logout global domain server
        client_domain.api_call("logout", {})

    # error occurred
    if find_host_res is False:
        return

    # if the auto assign flag is on and some changes were made on the global domain,
    # invoke assign-global-assignment on the relevant domains
    if is_auto_assign and global_domain_cloned_host_uid is not None:
        assign_global_domain_on_locals_domains(client, global_domain_name)
    else:
        log("\n\tThe auto assign flag is off, the global domain will not be assign. "
            "\n\tAs a result the local rules and groups which contains globals relevant objects will not be cloned")


def assign_global_domain_on_locals_domains(client, global_domain_name):
    """
    This method do assign on the domains that the global domain is currently assign on
    :param client: Api client of the domain
    :param global_domain_name: global domain name
    """
    # Retrieve global domain data in order to know on which domains to assign
    show_global_domain = client.api_call("show-global-domain", {"name": global_domain_name, "details-level": "full"})
    if show_global_domain.success is False:
        log("\n\tFailed to get the global domains data, cannot assign global domain: {}"
            .format(show_global_domain.error_message))
        return

    # check if the global domain assign on other domains and assign the changes if auto_assign turn on
    if show_global_domain.data["global-domain-assignments"]:
        for local_domain in show_global_domain.data["global-domain-assignments"]:
            # assign global assignment to local domain
            log("\n\tAssign global domain on local domain: " + local_domain["dependent-domain"])
            assign = client.api_call("assign-global-assignment", {"global-domains": global_domain_name,
                                                                  "dependent-domains": local_domain[
                                                                      "dependent-domain"]})
            if assign.success is False:
                log("\n\tFailed to assign the global domain on the local")
                continue
    else:
        log("There are no domains to assign the changes")


def discard_write_to_log_file(api_client, message):
    """
    This method discards the changes for a given api client and save message to the log file
    :param api_client: Api client of the domain
    :param message: message that will be written to log file
    """
    api_client.api_call("discard", {})
    log("\n\t!" + message)


def write_message_close_log_file_and_exit(message):
    """
    This method writes message to log file close log file and exit the function
    :param message: message that will be written to log file
    """
    global log_file
    log(message)
    log_file.close()
    exit(1)


def log(message):
    """
    This method writes message to the log file and print it
    :param message: message that will be written to log file
    """
    global log_file
    print(message.encode("utf-8"), file=log_file)
    print(message)


def main(argv):
    # Initialize arguments
    global_domain = "Global"
    auto_assign = False

    if argv:
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", type=str, action="store", help="Server IP address or hostname", dest="server")
        parser.add_argument("-u", type=str, action="store", help="User name", dest="username")
        parser.add_argument("-p", type=str, action="store", help="Password", dest="password")
        parser.add_argument("-o", type=str, action="store", help="Original host IP", dest="origin_ip")
        parser.add_argument("-n", type=str, action="store", help="New host name", dest="new_name")
        parser.add_argument("-m", type=str, action="store", help="New host IP", dest="new_ip")
        parser.add_argument("-g", type=str, action="store", help="Global domain name", dest="global_name")
        parser.add_argument("-a", action="store_true", default=False,
                            help="Indicates that the script will do assign of global domain")

        args = parser.parse_args()

        required = "server username password origin_ip new_name new_ip".split()
        for r in required:
            if args.__dict__[r] is None:
                parser.error("parameter '%s' required" % r)

        server = args.server
        username = args.username
        password = args.password
        orig_host_ip = args.origin_ip
        cloned_host_name = args.new_name
        cloned_host_ip = args.new_ip
        auto_assign = args.a

        if args.global_name is not None:
            global_domain = args.global_name

    else:
        server = input("Enter server IP address or hostname:")
        username = input("Enter username: ")

        if sys.stdin.isatty():
            password = getpass.getpass("Enter password: ")
        else:
            print("Attention! Your password will be shown on the screen!")
            password = input("Enter password: ")

        orig_host_ip = input("Enter host IP address: ")
        cloned_host_name = input("Enter new host name: ")
        assert isinstance(cloned_host_name, str)
        cloned_host_ip = input("Enter new host server IP :")
        global_domain_input = input("Enter global domain name in case of MDS server: "
                                    "[In order to use the default "
                                    "value ('Global') or in case of CMA hit 'Enter']")

        if global_domain_input != "":
            global_domain = global_domain_input

        auto_assign_input = input("Enter 'True' if you want the script to do "
                                  "assign of the global domain [In order to use the default value "
                                  "('False') hit 'Enter']")

        if auto_assign_input != "" and auto_assign_input == "True":
            auto_assign = auto_assign_input

    with APIClient(APIClientArgs(server=server)) as client:
        # Creates debug file. The debug file contains all the communication
        # between the python script and Check Point's management server.
        client.debug_file = "api_calls.json"

        global log_file
        log_file = open('logfile.txt', 'w+')

        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he
        # accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        log("\n\tChecking the fingerprint for server {}...".format(server))
        if client.check_fingerprint() is False:
            write_message_close_log_file_and_exit("Could not get the server's fingerprint"
                                                  " - Check connectivity with the server.")

        # login to server
        log("\n\tLogging in to server {}...".format(server))
        login_res = client.login(username, password)
        if login_res.success is False:
            write_message_close_log_file_and_exit("Login failed: {}".format(login_res.error_message))

        # show session details in order to check if the server is MDS
        log("\n\tVerifying the type of server {}...".format(server))
        session_res = client.api_call("show-session", {}, login_res.data["sid"])
        if session_res.success is False:
            write_message_close_log_file_and_exit("Login failed: {}".format(session_res.error_message))

        # the server is not MDS, perform clone host only on the this server
        if session_res.data["domain"]["domain-type"] != "mds":
            log("\n\tLogged into SM server {}".format(server))
            find_host_by_ip_and_clone(client, orig_host_ip, cloned_host_name, cloned_host_ip)
        # the server is MDS, run clone host on each of the existing domains
        else:
            log("\n\tLogged into MD server {}".format(server))
            client_domain = APIClient(APIClientArgs(server=server))
            client_domain.debug_file = "api_domain_calls.json"

            try:
                # handle global domain
                log("\n\tChecking on Global Domain...")
                handle_global_domain(client, username, password, client_domain, global_domain, auto_assign,
                                     orig_host_ip, cloned_host_name, cloned_host_ip)

                # get list of domains
                domains = client.api_query("show-domains")
                if domains.success is False:
                    discard_write_to_log_file(client,
                                              "Failed to get the domains data: {}".format(domains.error_message))
                    # login out the MDS server
                    client.api_call("logout", {})
                    log_file.close()
                    exit(1)

                # go over all the existing domains
                for domain in domains.data:
                    log("\n\tChecking on Local Domain {}".format(domain["name"]))
                    handle_local_domain(client_domain, domain, username, password, orig_host_ip, cloned_host_name,
                                        cloned_host_ip)
            finally:
                client_domain.save_debug_data()

        # close the log file
        log_file.close()


if __name__ == "__main__":
    main(sys.argv[1:])
