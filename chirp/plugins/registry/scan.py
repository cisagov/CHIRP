"""Main method for the Windows registry plugin."""

# Standard Python Libraries
import json
import logging
import os
from typing import Dict, List, Tuple, Union

# cisagov Libraries
from chirp.common import OUTPUT_DIR, REGISTRY, build_report
from chirp.plugins import operators
from chirp.plugins.registry.registry import enumerate_registry_values


async def check_matches(
    indicator_list: List[Tuple[str, str]], registry_key: str
) -> Tuple[int, List[Dict[str, str]], Union[str, dict]]:
    """Check for registry key matches to a list of indicators.

    :param indicator_list: A list containing tuples of keys and search strings
    :type indicator_list: List[Tuple[str,str]]
    :param registry_key: A registry key to query
    :type registry_key: str
    :return: A tuple of (hits, the search criteria, matches)
    :rtype: Tuple[int, List[Dict[str,str]], Union[str, dict]]
    """
    hits = 0
    search_criteria = []
    match = ""
    for key, search_string in indicator_list:
        _match = None
        if not match:
            if operators.searcher(search_string, registry_key, key.lower()):
                _match = registry_key
        else:
            if operators.searcher(search_string, match, key.lower()):
                _match = match
        hits += 1
        search_criteria.append({"key": str(key), "search_string": search_string})
        if _match:
            match = _match
    return hits, search_criteria, match


async def _report_hits(indicator: str, vals: dict) -> None:
    """Write to the log the number of hits for a given indicator."""
    logging.log(
        REGISTRY,
        "Found {} hit(s) for {} indicator.".format(len(vals["matches"]), indicator),
    )


async def run(indicators: dict) -> None:
    """Accept a dict containing events indicators and write out to the OUTPUT_DIR specified by chirp.common.

    :param indicators: A dict containing parsed registry indicator files.
    :type indicators: dict
    """
    if not indicators:
        return
    logging.debug("(REGISTRY) Entered registry plugin.")
    report = {indicator["name"]: build_report(indicator) for indicator in indicators}
    for indicator in indicators:
        ind = indicator["indicator"]
        indicator_list = [(k, v) for k, v in ind.items() if k != "registry_key"]
        logging.log(REGISTRY, "Reading {}".format(ind["registry_key"]))
        async for value in enumerate_registry_values(ind["registry_key"]):
            if value == "ERROR":
                logging.log(REGISTRY, "Hit an error, exiting.")
                return
            hits, search_criteria, match = await check_matches(indicator_list, value)
            if hits != len(indicator_list):
                continue
            report[indicator["name"]]["_search_criteria"] = search_criteria
            if match:
                report[indicator["name"]]["matches"].append(match)
    [await _report_hits(k, v) for k, v in report.items()]
    with open(os.path.join(OUTPUT_DIR, "registry.json"), "w+") as writeout:
        writeout.write(
            json.dumps({r: report[r] for r in report if report[r]["matches"]})
        )
