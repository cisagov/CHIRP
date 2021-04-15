"""Parsing logic for inputted Network.py-gathered data."""

# Standard Python Libraries
import json
import logging
import os
from typing import List

# cisagov Libraries
from chirp.common import NETWORK, OUTPUT_DIR, build_report
from chirp.plugins.network.network import (
    grab_dns,
    grab_netstat,
    parse_dns,
    parse_netstat,
)


async def hunter(records: List[bytes], ioc: str) -> bool:
    """Return if any record in a list of records matches a given IoC.

    :param records: A list of network records
    :type records: List[str]
    :param ioc: An indicator to check against record
    :type ioc: str
    :return: If any record in the list of records matches the IoC
    :rtype: bool
    """
    return any(str.encode(ioc.lower()) in record.lower() for record in records)


async def run(indicators: dict) -> None:
    """Accept a dict containing events indicators and writes out to the OUTPUT_DIR specified by chirp.common.

    :param indicators: A dict containing parsed network indicator files.
    :type indicators: dict
    """
    if not indicators:
        return

    hits = 0
    logging.debug("Entered network plugin.")
    saved_ns = parse_netstat(grab_netstat())
    saved_dns = parse_dns(grab_dns())

    report = {indicator["name"]: build_report(indicator) for indicator in indicators}

    for indicator in indicators:
        try:
            for ioc in indicator["indicator"]["ips"].splitlines():
                if await hunter(saved_ns + saved_dns, ioc):
                    report[indicator["name"]]["matches"].append(ioc)
                    hits += 1
        except KeyError:
            logging.log(NETWORK, "{} appears to be malformed.".format(indicator))
    logging.log(
        NETWORK,
        "Read {} records, found {} IoC hits.".format(
            len(saved_dns) + len(saved_ns), hits
        ),
    )

    with open(os.path.join(OUTPUT_DIR, "network.json"), "w+") as writeout:
        writeout.write(
            json.dumps({r: report[r] for r in report if report[r]["matches"]})
        )
