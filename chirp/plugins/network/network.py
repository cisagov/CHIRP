"""Will acquire forensic data ready to parse by __scan__.py."""

# Standard Python Libraries
import subprocess  # nosec
from typing import List


def grab_netstat() -> bytes:
    """Grab the output of `netstat -abno` (requires admin).

    :return: Output of `netstat -abno`
    :rtype: bytes
    """
    return subprocess.check_output("netstat -abno")  # nosec


def grab_dns() -> bytes:
    """Grab the output of `ipconfig /displaydns`.

    :return: Output of `ipconfig /displaydns`
    :rtype: bytes
    """
    return subprocess.check_output("ipconfig /displaydns")  # nosec


def parse_dns(dns: bytes) -> List[str]:
    """Parse the output of grab_dns, returning a list of parsed values that we would like to search.

    :param dns: Output of grab_dns
    :type dns: bytes
    :return: A list of parsed values (Record Name, CNAME, A (HOST))
    :rtype: List[str]
    """
    dnsrecords = dns
    temp_list = []

    for line in dnsrecords.decode().splitlines():
        temp_line = line.lstrip()
        if (
            temp_line.startswith("Record Name")
            or temp_line.startswith("CNAME")
            or temp_line.startswith("A (Host)")
        ):
            temp_list.append(temp_line.split(": ")[1])

    return temp_list


def parse_netstat(netstat: bytes) -> List[str]:
    """Parse the output of grab_netstat, returning a list of parsed values that we would like to search.

    :param netstat: Output of grab_dns
    :type netstat: bytes
    :return: A list of parsed values
    :rtype: List[str]
    """
    netstatrecords = netstat
    temp_list = []

    for line in netstatrecords.decode().splitlines():
        if len(line.split()) > 2 or line.lstrip().startswith("Proto"):
            ip = line.split()[2]
            if ip not in ["*:*", "obtain", "[::]:0"]:
                temp_list.append(ip)

    return temp_list
