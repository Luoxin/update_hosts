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


def is_internal_ip(ip_str):
    s = ""
    for item in ip_str.split("."):
        if (len(item)) == 1:
            item = "00" + item
        if (len(item)) == 2:
            item = "0" + item
        s = s + "." + item
    s = s.lstrip(".")

    base_list = [
        ["010.000.000.000", "010.255.255.255"],  # A
        ["172.016.000.000", "172.031.255.255"],  # B
        ["192.168.000.000", "192.168.255.255"],  # C
        ["100.064.000.000", "100.127.255.255"],  # ISP
        ["169.254.000.000", "169.254.255.255"],  # DHCP
        ["127.000.000.000", "127.255.255.255"],  # LOCAL
    ]

    for item in base_list:
        if item[0] <= s <= item[1]:
            return True

    return False


if __name__ == "__main__":
    for ip in [
        "10.20.0.111",
        "10.10.42.1",
        "100.64.228.13",
        "221.222.222.33",
        "8.8.8.8",
        "114.114.144.114",
        "192.168.31.46",
        "127.0.0.1",
    ]:
        print(
            "is_internal_ip: ip: %s, \t result: %s" % (ip, is_internal_ip(ip))
        )  # 方法1：掩码对比
