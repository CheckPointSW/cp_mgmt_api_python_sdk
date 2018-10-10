# cp_mgmt_api_python_sdk
Check Point API Python Development Kit simplifies the usage of the Check Point R80.10 Management APIs. The kit contains the API library project, and sample projects demonstrating the capabilities of the library.

## Setup
1. Clone this repo
2. cd to the repo root dir and install the module using `pip2`:
  1. In user mode:
      ```
      $ pip2 install --user .
      ```
  1. Or, system-wide:
      ```
      # pip2 install .
      ```
3. Now, you can import this module from any python script.

## Content
`cp_mgmt_api_python_sdk` - the API library project.

`sample/add_access_rule` - demonstrates a basic flow of using the APIs: performs a login command, adds an access rule to the top of the access policy layer, and publishes the changes.

`sample/clone_host` - demonstrates cloning and replacing an existing host with a cloned host.

`sample/discard_sessions` - demonstrates how to discard the changes to the database for un-published sessions.

`sample/find_duplicate_ip` - demonstrates searching for all the hosts that share the same IP address.

## Development Environment
The kit is developed using Python language version 2.7.9
