"""
    api_command_formatter.py
    version 1.1

    Represents an API Command. Later, we can use this object to:
    a. Make a web service call using the parameters dictionary and the format_fommand_and_verb function
    b. Make a command-line call using the tostring function

    SmartConsole Extensions present an interesting case:
    Read-only calls must be executed with web service calls,
    while read-only calls must be
    confirmed by the users as they see them in command-line mode,
    then run by SmartConsole in command-line mode.

    This class helps to serialize to both syntactic ways.

    written by: Check Point software technologies inc.
"""
from enum import Enum


class APIFormat(Enum):
    COMMAND_LINE = 1
    WEB_SERVICE = 2


class APICommand:
    def __init__(self, verb, command, parameters):
        self.verb = verb
        self.command = command
        self.parameters = parameters

    def format_command_and_verb(self, api_format):
        # command-line calls: verb command example set host
        # web service calls: verb-command example: set-host
        verb_command_separator = " " if api_format == APIFormat.COMMAND_LINE else "-"
        return self.verb + verb_command_separator + self.command

    def tostring(self, api_format):
        return self.format_command_and_verb(api_format) + " " + self.serialize_parameters(self.parameters, None)

    # serializes a parameter of type dictionary.
    # example input: {"position": {"above": "Cleanup Rule"}}
    # example output: position.above "Cleanup Rule"
    def serialize_dictionary(self, dictionary, prefix):
        result = ""
        prefix = "" if not prefix else prefix + "."

        for (key, value) in dictionary.items():
            param_prefix = prefix + key
            result += " " + self.serialize_parameters(value, param_prefix)

        # remove the extra space that we put in the beginning
        return result[1:]

    # serializes a parameter of type list.
    # example input: {"members": ["BranchOfficeVM", "RemoteMachine"]}
    # example output: members.1 BranchOfficeVM members.2 RemoteMachine
    def serialize_list(self, list, prefix):

        result = ""
        for index, item in enumerate(list):
            result + " " + self.serialize_parameters(item, (index+1))

        # remove the extra space that we put in the beginning
        return result[1:]

    # serializes a parameter of a primitive type.
    # example input: {"color": "red"}
    # example output: color red
    def serialize_primitive(self, primitive, prefix):
        return prefix + " \"" + str(primitive) + "\""

    def serialize_parameters(self, value, param_prefix):

        if isinstance(value, list):
            return self.serialize_list(value, param_prefix)
        elif isinstance(value, dict):
            return self.serialize_dictionary(value, param_prefix)
        else:
            return self.serialize_primitive(value, param_prefix)
