#
# cp_management_api.py
# version 1.1
#
# A library for communicating with Check Point's management server using [2.7.9 < python < 3]
# written by: Check Point software technologies inc.
# October 2016
# tested with Check Point R80 (tested with take hero2 198)
#

from __future__ import print_function

import sys

# compatible import for python 2 and 3
from .api_exceptions import APIException, APIClientException, TimeoutException
from .api_response import APIResponse
from cpapi.utils import get_massage_from_io_error, compatible_loads

if sys.version_info >= (3, 0):
    import http.client as http_client
else:
    import httplib as http_client

import hashlib
import json
import os.path
import ssl
import subprocess
import time


class APIClientArgs:
    """
    This class provides arguments for APIClient configuration.
    All the arguments are configured with their default values.
    """

    # port is set to None by default, but it gets replaced with 443 if not specified
    # context possible values - web_api (default) or gaia_api
    # single_conn is set to True by default, when work on parallel set to False
    def __init__(self, port=None, fingerprint=None, sid=None, server="127.0.0.1", http_debug_level=0,
                 api_calls=None, debug_file="", proxy_host=None, proxy_port=8080,
                 api_version=None, unsafe=False, unsafe_auto_accept=False, context="web_api", single_conn=True,
                 user_agent="python-api-wrapper", sync_frequency=2, cloud_mgmt_id=""):
        self.port = port
        # management server fingerprint
        self.fingerprint = fingerprint
        # session-id.
        self.sid = sid
        # management server name or IP-address
        self.server = server
        # debug level
        self.http_debug_level = http_debug_level
        # an array with all the api calls (for debug purposes)
        self.api_calls = api_calls if api_calls else []
        # name of debug file. If left empty, debug data will not be saved to disk.
        self.debug_file = debug_file
        # HTTP proxy server address (without "http://")
        self.proxy_host = proxy_host
        # HTTP proxy port
        self.proxy_port = proxy_port
        # Management server's API version
        self.api_version = api_version
        # Indicates that the client should not check the server's certificate
        self.unsafe = unsafe
        # Indicates that the client should automatically accept and save the server's certificate
        self.unsafe_auto_accept = unsafe_auto_accept
        # The context of using the client - defaults to web_api
        self.context = context
        # Indicates that the client should use single HTTPS connection
        self.single_conn = single_conn
        # User agent will be use in api call request header
        self.user_agent = user_agent
        # Interval size in seconds of the task update
        self.sync_frequency = sync_frequency
        # Smart-1 Cloud management UID
        self.cloud_mgmt_id = cloud_mgmt_id


class APIClient:
    """
    APIClient encapsulates everything that the user needs to do for communicating with a Check Point management server
    """

    def __init__(self, api_client_args=None):
        """Constructor
        :param api_client_args: APIClientArgs object containing arguments
        """
        # if a client_args is not supplied, make a default one
        if api_client_args is None:
            api_client_args = APIClientArgs()
        # port on management server
        self.__port, self.__is_port_default = (api_client_args.port, False) if api_client_args.port else (443, True)
        # management server fingerprint
        self.fingerprint = api_client_args.fingerprint
        # session-id.
        self.sid = api_client_args.sid
        # management server name or IP-address
        self.server = api_client_args.server
        # domain to log into in an MDS environment
        self.domain = None
        # debug level
        self.http_debug_level = api_client_args.http_debug_level
        # an array with all the api calls (for debug purposes)
        self.api_calls = api_client_args.api_calls
        # name of debug file. If left empty, debug data will not be saved to disk.
        self.debug_file = api_client_args.debug_file
        # HTTP proxy server address
        self.proxy_host = api_client_args.proxy_host
        # HTTP proxy port
        self.proxy_port = api_client_args.proxy_port
        # Management server's API version
        self.api_version = api_client_args.api_version
        # Indicates that the client should not check the server's certificate
        self.unsafe = api_client_args.unsafe
        # Indicates that the client should automatically accept and save the server's certificate
        self.unsafe_auto_accept = api_client_args.unsafe_auto_accept
        # The context of using the client - defaults to web_api
        self.context = api_client_args.context
        # HTTPS connection
        self.conn = None
        # Indicates that the client should use single HTTPS connection
        self.single_conn = api_client_args.single_conn
        # User agent will be use in api call request header
        self.user_agent = api_client_args.user_agent
        # Interval size in seconds of the task update
        self.sync_frequency = api_client_args.sync_frequency
        # Smart-1 Cloud management UID
        self.cloud_mgmt_id = api_client_args.cloud_mgmt_id

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """destructor"""
        # if sid is not empty (the login api was called), then call logout
        if self.sid:
            self.api_call("logout")
        self.close_connection()
        # save debug data with api calls to disk
        self.save_debug_data()

    def get_port(self):
        """returns the port of the API client (int)"""
        return self.__port

    def is_port_default(self):
        """returns whether the user changed the port (bool)"""
        return self.__is_port_default

    def set_port(self, port):
        self.__port = port
        self.__is_port_default = False

    def save_debug_data(self):
        """save debug data with api calls to disk"""
        if self.debug_file:
            print("\nSaving data to debug file {}\n".format(self.debug_file), file=sys.stderr)
            out_file = open(self.debug_file, 'w+')
            out_file.write(json.dumps(self.api_calls, indent=4, sort_keys=True))

    def _common_login_logic(self, credentials, continue_last_session, domain, read_only, payload):
        if self.context == "web_api":
            credentials.update({"continue-last-session": continue_last_session,
                                "read-only": read_only})

        if domain:
            credentials.update({"domain": domain})
        if isinstance(payload, dict):
            credentials.update(payload)

        login_res = self.api_call("login", credentials)

        if login_res.success:
            self.sid = login_res.data["sid"]
            self.domain = domain
            if self.api_version is None:
                self.api_version = login_res.data["api-server-version"]
        return login_res

    def login_with_api_key(self, api_key, continue_last_session=False, domain=None, read_only=False,
              payload=None):
        """
        performs a 'login' API call to the management server

        :param api_key: Check Point api-key
        :param continue_last_session: [optional] It is possible to continue the last Check Point session
                                      or to create a new one
        :param domain: [optional] The name, UID or IP-Address of the domain to login.
        :param read_only: [optional] Login with Read Only permissions. This parameter is not considered in case
                          continue-last-session is true.
        :param payload: [optional] More settings for the login command
        :returns: APIResponse object
        :side-effects: updates the class's uid and server variables
        """
        credentials = {"api-key": api_key}

        return self._common_login_logic(credentials, continue_last_session, domain, read_only, payload)

    def login(self, username, password, continue_last_session=False, domain=None, read_only=False,
              payload=None):
        """
        performs a 'login' API call to the management server

        :param username: Check Point admin name
        :param password: Check Point admin password
        :param continue_last_session: [optional] It is possible to continue the last Check Point session
                                      or to create a new one
        :param domain: [optional] The name, UID or IP-Address of the domain to login.
        :param read_only: [optional] Login with Read Only permissions. This parameter is not considered in case
                          continue-last-session is true.
        :param payload: [optional] More settings for the login command
        :returns: APIResponse object
        :side-effects: updates the class's uid and server variables
        """
        credentials = {"user": username, "password": password}

        return self._common_login_logic(credentials, continue_last_session, domain, read_only, payload)

    def login_as_root(self, domain=None, payload=None):
        """
        This method allows to login into the management server with root permissions.
        In order to use this method the application should be run directly on the management server
        and to have super-user privileges.

        :param domain: [optional] name/uid/IP address of the domain you want to log into in an MDS environment
        :param payload: [optional] dict of additional parameters for the login command
        :return: APIResponse object with the relevant details from the login command.
        """
        python_absolute_path = os.path.expandvars("$MDS_FWDIR/Python/bin/python3")
        api_get_port_absolute_path = os.path.expandvars("$MDS_FWDIR/scripts/api_get_port.py")
        mgmt_cli_absolute_path = os.path.expandvars("$CPDIR/bin/mgmt_cli")

        # try to get the management server's port by running a script
        if not self.is_port_default():
            port = self.get_port()
        else:
            try:
                port = compatible_loads(subprocess.check_output([python_absolute_path,
                                                                api_get_port_absolute_path, "-f", "json"]))["external_port"]
            # if can't, default back to what the user wrote or the default (443)
            except (ValueError, subprocess.CalledProcessError):
                port = self.get_port()

            else:
                # may be a non-standard port, update the configuration to reflect this,
                # required for follow-up HTTPS connections
                self.set_port(port)

        try:
            # This simple dict->cli format works only because the login command doesn't require
            # any complex parameters like objects and lists
            new_payload = []
            if payload:
                for key in payload.keys():
                    new_payload += [key, payload[key]]
            if domain:
                new_payload += ["domain", domain]
            login_response = compatible_loads(subprocess.check_output(
                [mgmt_cli_absolute_path, "login", "-r", "true", "-f", "json", "--port", str(port), "--user-agent",
                 self.user_agent] + new_payload))
            self.sid = login_response["sid"]
            self.server = "127.0.0.1"
            self.domain = domain
            if self.api_version is None:
                self.api_version = login_response["api-server-version"]
            return APIResponse(login_response, success=True)
        except ValueError as err:
            raise APIClientException(
                "Could not load JSON from login as root command, perhaps no root privileges?\n" + str(
                    type(err)) + " - " + str(err))
        except subprocess.CalledProcessError as err:
            raise APIClientException("Could not login as root:\n" + str(type(err)) + " - " + str(err))
        except (WindowsError) as err:
            raise APIClientException("Could not login as root:\n" + str(type(err)) + " - " + str(err))

    def api_call(self, command, payload=None, sid=None, wait_for_task=True, timeout=-1):
        """
        performs a web-service API request to the management server

        :param command: the command is placed in the URL field
        :param payload: a JSON object (or a string representing a JSON object) with the command arguments
        :param sid: [optional]. The Check Point session-id. when omitted use self.sid.
        :param wait_for_task: determines the behavior when the API server responds with a "task-id".
                              by default, the function will periodically check the status of the task
                              and will not return until the task is completed.
                              when wait_for_task=False, it is up to the user to call the "show-task" API and check
                              the status of the command.
        :param timeout: Optional positive timeout (in seconds) before stop waiting for the task even if not completed.
        :return: APIResponse object
        :side-effects: updates the class's uid and server variables
        """
        timeout_start = time.time()
        if self.check_fingerprint() is False:
            return APIResponse("", False, err_message="Invalid fingerprint")
        if payload is None:
            payload = {}
        # Convert the json payload to a string if needed
        if isinstance(payload, str):
            _data = payload
        elif isinstance(payload, dict):
            _data = json.dumps(payload, sort_keys=False)
        else:
            raise TypeError('Invalid payload type - must be dict/string')
        # update class members if needed.
        if sid is None:
            sid = self.sid

        # Set headers
        _headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Content-Length": len(_data),
            "Connection": "Keep-Alive"
        }

        # In all API calls (except for 'login') a header containing the Check Point session-id is required.
        if sid is not None:
            _headers["X-chkp-sid"] = sid

        # init https connection. if single connection is True, use last connection
        conn = self.get_https_connection()

        url = ""
        if self.cloud_mgmt_id != "":
            url += "/" + self.cloud_mgmt_id

        url += "/" + self.context

        if self.api_version:
            url += "/v" + str(self.api_version)

        url += "/" + command

        response = None
        try:
            # Send the data to the server
            conn.request("POST", url, _data, _headers)
            # Get the reply from the server
            response = conn.getresponse()
            res = APIResponse.from_http_response(response)
        except ValueError as err:
            if err.args[0] == "Fingerprint value mismatch":
                err_message = "Error: Fingerprint value mismatch:\n" + " Expecting : {}\n".format(
                    err.args[1]) + " Got: {}\n".format(
                    err.args[2]) + "If you trust the new fingerprint, edit the 'fingerprints.txt' file."
                res = APIResponse("", False, err_message=err_message)
            else:
                res = APIResponse("", False, err_message=err)
        except (http_client.CannotSendRequest, http_client.BadStatusLine, ConnectionAbortedError, BrokenPipeError, IOError) as e:
            self.conn = self.create_https_connection()
            self.conn.request("POST", url, _data, _headers)
            response = self.conn.getresponse()
            res = APIResponse.from_http_response(response)
        except Exception as err:
            res = APIResponse("", False, err_message=err)
        finally:
            if not self.single_conn:
                conn.close()

        if response:
            res.status_code = response.status

        # When the command is 'login' we'd like to convert the password to "****" so that it
        # would not appear as plaintext in the debug file.
        if command == "login":
            json_data = compatible_loads(_data)
            json_data["password"] = "****"
            _data = json.dumps(json_data)

        if self.debug_file:
            # Store the request and the reply (for debug purpose).
            _api_log = {
                "request": {
                    "url": url,
                    "payload": compatible_loads(_data),
                    "headers": _headers
                },
                "response": res.response()
            }
            self.api_calls.append(_api_log)

        # If we want to wait for the task to end, wait for it
        if wait_for_task is True and res.success and command != "show-task":
            if "task-id" in res.data:
                res = self.__wait_for_task(res.data["task-id"], timeout=(timeout - time.time() + timeout_start))
            elif "tasks" in res.data:
                res = self.__wait_for_tasks(res.data["tasks"], timeout=(timeout - time.time() + timeout_start))

        return res

    def api_query(self, command, details_level="standard", container_key="objects", include_container_key=False,
                  payload=None):
        """
        The APIs that return a list of objects are limited by the number of objects that they return.
        To get the full list of objects, there's a need to make repeated API calls each time using a different offset
        until all the objects are returned.
        This API makes such repeated API calls and return the full list objects.
        note: this function calls gen_api_query and iterates over the generator until it gets all the objects,
        then returns.

        :param command: name of API command. This command should be an API that returns an array of
                        objects (for example: show-hosts, show networks, ...)
        :param details_level: query APIs always take a details-level argument.
                              possible values are "standard", "full", "uid"
        :param container_key: name of the key that holds the objects in the JSON response (usually "objects").
        :param include_container_key: If set to False the 'data' field of the APIResponse object
                                      will be a list of the wanted objects.
                                      Otherwise, the date field of the APIResponse will be a dictionary in the following
                                      format: { container_key: [ List of the wanted objects], "total": size of the list}
        :param payload: a JSON object (or a string representing a JSON object) with the command arguments
        :return: if include-container-key is False:
                     an APIResponse object whose .data member contains a list of the objects requested: [ , , , ...]
                 if include-container-key is True:
                     an APIResponse object whose .data member contains a dict: { container_key: [...], "total": n }
        """
        api_res = None
        for api_res in self.gen_api_query(command, details_level, [container_key], payload=payload):
            pass
        if api_res and api_res.success and container_key in api_res.data and include_container_key is False:
            api_res.data = api_res.data[container_key]
        return api_res

    def gen_api_query(self, command, details_level="standard", container_keys=None, payload=None):
        """
        This is a generator function that yields the list of wanted objects received so far from the management server.
        This is in contrast to normal API calls that return only a limited number of objects.
        This function can be used to show progress when requesting many objects (i.e. "Received x/y objects.")

        :param command: name of API command. This command should be an API that returns an array of objects
                        (for example: show-hosts, show networks, ...)
        :param details_level: query APIs always take a details-level argument. Possible values are "standard", "full", "uid"
        :param container_keys: the field in the .data dict that contains the objects
        :param payload: a JSON object (or a string representing a JSON object) with the command arguments
        :yields: an APIResponse object as detailed above
        """

        finished = False  # will become true after getting all the data
        all_objects = {}  # accumulate all the objects from all the API calls

        # default
        if container_keys is None:
            container_keys = ["objects"]

        # if given a string, make it a list
        if sys.version_info >= (3, 0):
            if isinstance(container_keys, (str, str)):
                container_keys = [container_keys]
        else:
            if isinstance(container_keys, (str, unicode)):
                container_keys = [container_keys]

        for key in container_keys:
            all_objects[key] = []
        iterations = 0  # number of times we've made an API call
        limit = 50 # page size to get for each api call
        offset = 0 # skip n objects in the database
        if payload is None:
            payload = {}
        else:
            limit = int(payload.get("limit", limit))
            offset = int(payload.get("offset", offset))

        payload.update({"limit": limit, "offset": iterations * limit + offset, "details-level": details_level})
        api_res = self.api_call(command, payload)
        for container_key in container_keys:
            if not api_res.data or container_key not in api_res.data or not isinstance(api_res.data[container_key], list) \
                    or "total" not in api_res.data or api_res.data["total"] == 0:
                finished = True
                yield api_res
                break

        # are we done?
        while not finished:
            # make the API call, offset should be increased by 'limit' with each iteration
            if api_res.success is False:
                raise APIException(api_res.error_message, api_res.data)

            total_objects = api_res.data["total"]  # total number of objects
            received_objects = api_res.data["to"]  # number of objects we got so far
            for container_key in container_keys:
                all_objects[container_key] += api_res.data[container_key]
                api_res.data[container_key] = all_objects[container_key]
            # yield the current result
            yield api_res
            # did we get all the objects that we're supposed to get
            if received_objects == total_objects:
                break

            iterations += 1
            payload.update({"limit": limit, "offset": iterations * limit + offset, "details-level": details_level})
            api_res = self.api_call(command, payload)

    def get_server_fingerprint(self):
        """
        Initiates an HTTPS connection to the server if need and extracts the SHA1 fingerprint from the server's certificate.
        :return: string with SHA1 fingerprint (all uppercase letters)
        """
        conn = self.get_https_connection()
        fingerprint_hash = conn.get_fingerprint_hash()
        if not self.single_conn:
            conn.close()
        return fingerprint_hash

    def __wait_for_task(self, task_id, timeout=-1):
        """
        When the server needs to perform an API call that may take a long time (e.g. run-script, install-policy,
        publish), the server responds with a 'task-id'.
        Using the show-task API it is possible to check on the status of this task until its completion.
        Every two seconds, this function will check for the status of the task.
        The function will return when the task (and its sub-tasks) are no longer in-progress.

        :param task_id: The task identifier.
        :param timeout: Optional positive timeout (in seconds) that will end the task even if not completed.
        :return: APIResponse object (response of show-task command).
        :raises APIException
        """
        task_complete = False
        task_result = None
        task_start = time.time()
        in_progress = "in progress"

        # As long as there is a task in progress or the timeout isn't expired (and is positive)
        while not task_complete:

            # If timeout parameter was set and valid and timeout did expire, raise exception
            if timeout >= 0 and time.time() - task_start > timeout:
                raise TimeoutException("Timeout reached when waiting for task to complete")

            # Check the status of the task
            task_result = self.api_call("show-task", {"task-id": task_id, "details-level": "full"}, self.sid, False)

            attempts_counter = 0
            while task_result.success is False:
                if attempts_counter < 5:
                    attempts_counter += 1
                    time.sleep(2)
                    task_result = self.api_call("show-task", {"task-id": task_id, "details-level": "full"},
                                                self.sid, False)
                else:
                    raise APIException(
                        "ERROR: Failed to handle asynchronous tasks as synchronous, tasks result is undefined",
                        task_result)

            # Count the number of tasks that are not in-progress
            completed_tasks = sum(1 for task in task_result.data["tasks"] if task["status"] != in_progress)

            # Get the total number of tasks
            total_tasks = len(task_result.data["tasks"])

            # Are we done?
            if completed_tasks == total_tasks:
                task_complete = True
            else:
                time.sleep(self.sync_frequency)  # Wait for sync_frequency seconds

        self.check_tasks_status(task_result)
        return task_result

    def __wait_for_tasks(self, task_objects, timeout=-1):
        """
        The version of __wait_for_task function for the collection of tasks

        :param task_objects: A list of task objects
        :return: APIResponse object (response of show-task command).
        """
        timeout_start = time.time()

        # A list of task ids to be retrieved
        tasks = []
        for task_obj in task_objects:
            # Retrieve the taskId and wait for the task to be completed
            task_id = task_obj["task-id"]
            tasks.append(task_id)
            self.__wait_for_task(task_id, timeout=(timeout - time.time() + timeout_start))

        task_result = self.api_call("show-task", {"task-id": tasks, "details-level": "full"},
                                    self.sid, False)

        APIClient.check_tasks_status(task_result)
        return task_result

    @staticmethod
    def check_tasks_status(task_result):
        """
        This method checks if one of the tasks failed and if so, changes the response status to be False

        :param task_result: api_response returned from "show-task" command
        :return:
        """
        for task in task_result.data["tasks"]:
             if task["status"] == "failed" or task["status"] == "partially succeeded" or task["status"] == "in progress":
                task_result.set_success_status(False)
                break

    def check_fingerprint(self):
        """
        This function checks if the server's certificate is stored in the local fingerprints file.
        If the server's fingerprint is not found, an HTTPS connection is made to the server
        and the user is asked if he or she accepts the server's fingerprint.
        If the fingerprint is trusted, it is stored in the fingerprint file.

        :return: False if the user does not accept the server certificate, True in all other cases.
        """
        if self.unsafe:
            return True
        # Read the fingerprint from the local file
        local_fingerprint = self.read_fingerprint_from_file(self.server)
        server_fingerprint = self.get_server_fingerprint()

        #Check if fingerprint is passed and matches
        if self.fingerprint == server_fingerprint:
            return True

        # If the fingerprint is not stored in the local file
        if local_fingerprint == "" or \
                local_fingerprint.replace(':', '').upper() != server_fingerprint.replace(':', '').upper():
            # Get the server's fingerprint with a socket.
            if server_fingerprint == "":
                return False

            if self.unsafe_auto_accept:
                self.save_fingerprint_to_file(self.server, server_fingerprint)
                return True

            if local_fingerprint == "":
                print("You currently do not have a record of this server's fingerprint.", file=sys.stderr)
            else:
                print(
                    "The server's fingerprint is different from your local record of this server's fingerprint.\n"
                    "You maybe a victim to a Man-in-the-Middle attack, please beware.", file=sys.stderr)
            print("Server's fingerprint: {}".format(server_fingerprint), file=sys.stderr)

            if self.ask_yes_no_question("Do you accept this fingerprint?"):
                if self.save_fingerprint_to_file(self.server, server_fingerprint):
                    print("Fingerprint saved.", file=sys.stderr)
                else:
                    print("Could not save fingerprint to file. Continuing anyway.", file=sys.stderr)
            else:
                return False

        self.fingerprint = server_fingerprint  # set the actual fingerprint in the class instance
        return True

    @staticmethod
    def ask_yes_no_question(question):
        """
        helper function. Present a question to the user with Y/N options.

        :param question: The question to display to the user
        :return: 'True' if the user typed 'Y'. 'False' is the user typed 'N'
        """
        if sys.version_info >= (3, 0):
            answer = input(question + " [y/n] ")
        else:
            answer = raw_input(question + " [y/n] ")
        if answer.lower() == "y" or answer.lower() == "yes":
            return True
        else:
            return False

    @staticmethod
    def save_fingerprint_to_file(server, fingerprint, filename="fingerprints.txt"):
        """
        store a server's fingerprint into a local file.

        :param server: the IP address/name of the Check Point management server.
        :param fingerprint: A SHA1 fingerprint of the server's certificate.
        :param filename: The file in which to store the certificates. The file will hold a JSON structure in which
                         the key is the server and the value is its fingerprint.
        :return: 'True' if everything went well. 'False' if there was some kind of error storing the fingerprint.
        """
        if not fingerprint:
            return False

        if os.path.isfile(filename):
            try:
                with open(filename) as f:
                    json_dict = json.load(f)
            except ValueError as e:
                if e.message == "No JSON object could be decoded":
                    print("Corrupt JSON file: " + filename, file=sys.stderr)
                else:
                    print(e.message, file=sys.stderr)
                return False
            except IOError as e:
                print("Couldn't open file: " + filename + "\n" + get_massage_from_io_error(e), file=sys.stderr)
                return False
            except Exception as e:
                print(e, file=sys.stderr)
                return False
            else:
                if server in json_dict and json_dict[server] == fingerprint:
                    return True
                else:
                    json_dict[server] = fingerprint
        else:
            json_dict = {server: fingerprint}

        try:
            with open(filename, 'w') as filedump:
                json.dump(json_dict, filedump, indent=4, sort_keys=True)
                filedump.close()
            return True
        except IOError as e:
            print("Couldn't open file: " + filename + " for writing.\n" + get_massage_from_io_error(e),
                  file=sys.stderr)
        except Exception as e:
            print(e, file=sys.stderr)
            return False

    @staticmethod
    def read_fingerprint_from_file(server, filename="fingerprints.txt"):
        """
        reads a server's fingerprint from a local file.

        :param server: the IP address/name of the Check Point management server.
        :param filename: The file in which to store the certificates. The file will hold a JSON structure in which
                         the key is the server and the value is its fingerprint.
        :return: A SHA1 fingerprint of the server's certificate.
        """
        if sys.version_info >= (3, 0):
            assert isinstance(server, (str, str))
        else:
            assert isinstance(server, (str, unicode))

        if os.path.isfile(filename):
            try:
                with open(filename) as f:
                    json_dict = json.load(f)
            except ValueError as e:
                if e.message == "No JSON object could be decoded":
                    print("Corrupt JSON file: " + filename, file=sys.stderr)
                else:
                    print(e.message, file=sys.stderr)
            except IOError as e:
                print("Couldn't open file: " + filename + "\n" + get_massage_from_io_error(e),
                      file=sys.stderr)
            except Exception as e:
                print(e, file=sys.stderr)
            else:
                # file is ok and readable.
                if server in json_dict:
                    return json_dict[server]
        return ""

    def create_https_connection(self):
        context = ssl.create_default_context()
        context.check_hostname = True
        # create https connection
        if self.proxy_host and self.proxy_port:
            conn = HTTPSConnection(self.proxy_host, self.proxy_port, context=context)
            conn.set_tunnel(self.server, self.get_port())
        else:
            conn = HTTPSConnection(self.server, self.get_port(), context=context)

        # Set fingerprint
        conn.fingerprint = self.fingerprint

        # Set debug level
        conn.set_debuglevel(self.http_debug_level)
        conn.connect()
        return conn

    def get_https_connection(self):
        if self.single_conn:
            if self.conn is None:
                self.conn = self.create_https_connection()
            return self.conn
        return self.create_https_connection()

    def close_connection(self):
        if self.conn:
            self.conn.close()


class HTTPSConnection(http_client.HTTPSConnection):
    """
    A class for making HTTPS connections that overrides the default HTTPS checks (e.g. not accepting
    self-signed-certificates) and replaces them with a server fingerprint check.
    """
    def connect(self):
        http_client.HTTPConnection.connect(self)
        self.sock = ssl.wrap_socket(self.sock, self.key_file, self.cert_file, cert_reqs=ssl.CERT_NONE)

    def get_fingerprint_hash(self):
        if self.sock is None:
            self.connect()
        fingerprint = hashlib.new("SHA1", self.sock.getpeercert(True)).hexdigest()
        return fingerprint.upper()
