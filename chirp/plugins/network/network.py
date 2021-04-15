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


def parse_dns(dns: bytes) -> List[bytes]:
    """Parse the output of grab_dns, returning a list of parsed values that we would like to search.

    :param dns: Output of grab_dns
    :type dns: bytes
    :return: A list of parsed values (Record Name, CNAME, A (HOST))
    :rtype: List[bytes]
    """
    dnsrecords = dns.splitlines()
    search_terms = [b"A (Host)", b"CNAME", b"Record Name"]
    return [
        record.split(b":")[1].strip()
        for record in dnsrecords
        if any(x in record for x in search_terms)
    ]


def parse_netstat(netstat: bytes) -> List[bytes]:
    """Parse the output of grab_netstat, returning a list of parsed values that we would like to search.

    :param netstat: Output of grab_dns
    :type netstat: bytes
    :return: A list of parsed values
    :rtype: List[bytes]
    """
    netstatrecords = [x.lstrip() for x in netstat.splitlines()]
    temp_list = []
    for record in netstatrecords:
        if len(record.split()) > 2 or record.startswith(b"Proto"):
            ip = record.split()[2]
            if ip not in [b"*:*", b"obtain", b"[::]:0"]:
                temp_list.append(ip)
    return temp_list
