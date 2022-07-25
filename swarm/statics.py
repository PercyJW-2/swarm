import re
from enum import Enum
from typing import Tuple


class StandardMessages(Enum):
    """
    Messages that are used for core functionalities
    """
    ANNOUNCE = "announce"
    UPDATE_LAUNCH = "update"
    ACKNOWLEDGED = "acknowledged"
    HEARTBEAT = "heartbeat"
    GET_ADDRESSES = "addresses"
    GET_MASTER = "master"


class MessageToBig(Exception):
    """
    If a Message is too big for the specified buffer of the ConnectionManager this Exception is thrown
    """
    pass


class InvalidIPString(Exception):
    """
    If a String passed to string_to_ip_and_port that could not be parsed to an ip and a port this Exception is thrown
    """
    pass


def string_to_ip_and_port(message: str) -> Tuple[str, int]:
    """
    Parses Strings to a Tuple of a String and Integer that contain a Network Address and the Port. If the string is not
    valid a InvalidIPString Exception is thrown

    :param message: String that is parsed
    :return: parsed Tuple that contains the Address and Port
    """
    valid_ipv4 = re.compile(r"^(\d?\d?\d.){3}\d?\d?\d:(\d?){4}\d$")
    valid_ipv6 = re.compile(r"^([a-f\d:]+:+)+[a-f\d]+:(\d?){4}\d$")
    valid_address = re.compile(r"^(localhost)|(\*+.\*):(\d?){4}\d$")
    if (not valid_ipv4.match(message)) and (not valid_ipv6.match(message)) and (not valid_address.match(message)):
        raise InvalidIPString(f"'{message}' is not an valid ip address")
    msg_split = message.split(":")
    port = msg_split[-1]
    ip = ":".join(msg_split[0:-1])
    port = int(port)
    return ip, port
