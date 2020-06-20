import os
import re

import socket


def is_ipv4(entry):
    try:
        if socket.inet_aton(entry):
            return True
    except socket.error:
        return False


def is_ipv6(entry):
    try:
        if socket.inet_pton(socket.AF_INET6, entry):
            return True
    except socket.error:
        return False


def valid_hostnames(hostname_list):
    for entry in hostname_list:
        if len(entry) > 255:
            return False
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        if not all(allowed.match(x) for x in entry.split(".")):
            return False
    return True


def is_readable(path=None):
    if os.path.isfile(path) and os.access(path, os.R_OK):
        return True
    return False
