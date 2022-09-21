# cp_mgmt_api_python_sdk
Check Point API Python Development Kit simplifies the use of the Check Point Management APIs. The kit contains the API library files, and sample files demonstrating the 
capabilities of the library. The kit is compatible with python 2 and 3.

## Content
`cpapi` - the API library project.

`add_access_rule` - demonstrates a basic flow of using the APIs: performs a login command, adds an access rule to the top of the access policy layer, and publishes the changes.

`clone_host` - demonstrates cloning and replacing an existing host with a cloned host.

`discard_sessions` - demonstrates how to discard the changes to the database for un-published sessions.

`find_duplicate_ip` - demonstrates searching for all the hosts that share the same IP address.

###### For examples, see the relevant Python version folder.

## Instructions
### SDK usage from a remote machine
Install the SDK by using the pip tool or by downloading the repository.

#### Install with pip
Run:
```
pip install cp-mgmt-api-sdk
```
Or:
```
pip install git+https://github.com/CheckPointSW/cp_mgmt_api_python_sdk
```
###### Note: you might be required to use "sudo" for this command.
#### Download the repository
Clone the repository with this command:
```
git clone https://github.com/CheckPointSW/cp_mgmt_api_python_sdk
```
or by clicking on the _‘Download ZIP’_ button and using unzip. <br>

Navigate to `.../cp_mgmt_api_python_sdk/` directory and run:
```
pip install .
```

#### Upgrade 
Upgrade the SDK by using pip tool:
```
pip install --upgrade git+https://github.com/CheckPointSW/cp_mgmt_api_python_sdk
```
###### Note: you might be required to use "sudo" for this command.

#### Uninstall
Uninstall the SDK by using pip tool:
```
pip uninstall cp-mgmt-api-sdk
```
###### Note: you might be required to use "sudo" for this command.

### SDK usage from a management machine
Follow the instructions above in the ["Download the repository"](#download-the-repository) section, to download the repository but do *not* run `pip install .`

After the downloading, copy the SDK to the machine (use scp, WinSCP or similar tool).

Configure your environment variables
```
export PYTHONPATH=$PYTHONPATH:<“CP-SDK” FULL PATH>
```
For example, if you copied the SDK to the path “/home/admin/” the command will be: <br>
```export PYTHONPATH=$PYTHONPATH:/home/admin/cp_mgmt_api_python_sdk/```
###### Note: When downloading the repository, directory name will be cp_mgmt_api_python_sdk-master.

## Development Environment
The kit is developed using Python versions 2.7 and 3.7
