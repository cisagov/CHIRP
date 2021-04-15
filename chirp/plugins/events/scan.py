"""Main method for the Windows events plugin."""

# Standard Python Libraries
import json
import logging
import os
from typing import Dict, List, Tuple, Union

# Third-Party Libraries
import aiomultiprocess as aiomp

# cisagov Libraries
from chirp.common import EVENTS, OUTPUT_DIR, build_report
from chirp.plugins import operators
from chirp.plugins.events.events import gather


async def check_matches(
    indicator_list: List[Tuple[str, str]],
    event_id: Union[int, None],
    event_log: dict,
) -> Tuple[int, List[Dict[str, str]], Union[str, dict]]:
    """Check for indicator matches in an event log.

    :param indicator_list: A list containing tuples of keys and search strings.
    :type indicator_list: List[Tuple[str, str]]
    :param event_id: An event ID to query.
    :type event_id: Union[int, None]
    :param event_log: An event log being queried, represented as a dict.
    :type event_log: dict
    :return: A tuple of (hits, the search criteria, matches)
    :rtype: Tuple[int, List[Dict[str, str]], Union[str, dict]]
    """
    hits = 0
    search_criteria = []
    match = ""
    for key, search_string in indicator_list:
        _match = None
        if not match:
            if operators.searcher(search_string, event_log, key.lower()):
                _match = event_log
        else:
            if operators.searcher(search_string, match, key.lower()):
                _match = match
        hits += 1
        search_criteria.append(
            {
                "key": str(key),
                "search_string": search_string,
                "event_id": event_id,
            }
        )
        if _match:
            match = _match
    return hits, search_criteria, match


num_logs = 0


async def _run(run_args):
    """Gather events and check for matches."""
    (
        event_type,
        indicators,
        report,
        num_logs,
    ) = run_args  # Unpack our arguments (bundled to passthrough for multiprocessing)
    logging.log(EVENTS, "Reading {} event logs.".format(event_type.split("%4")[-1]))
    async for event_log in gather(event_type):  # Iterate over event logs
        if event_log == "ERROR":
            logging.log(EVENTS, "Hit an error, exiting.")
            return
        if event_log:
            num_logs += 1
            for indicator in indicators:
                ind = indicator["indicator"]
                if (
                    ind["event_type"] == event_type
                ):  # Make sure the ioc is intended for this log
                    if "event_id" in ind and str(
                        event_log["event"]["system"]["event_id"]["$"]
                    ) != str(
                        ind["event_id"]
                    ):  # If ioc looks for event_id, but there is a mismatch then skip
                        continue
                    elif "event_id" not in ind:
                        ind["event_id"] = None
                    indicator_list = [
                        (k, v)
                        for k, v in ind.items()
                        if k not in ["event_type", "event_id"]
                    ]
                    hits, search_criteria, match = await check_matches(
                        indicator_list, ind["event_id"], event_log
                    )  # Check to see if the indicator matches the event log
                    if hits != len(indicator_list):
                        continue
                    report[indicator["name"]]["_search_criteria"] = search_criteria
                    if match:
                        report[indicator["name"]]["matches"].append(
                            match
                        )  # Append to report because there is a match.
    return report, num_logs


async def run(indicators: dict) -> None:
    """Accept a dict containing events indicators and writes out to the OUTPUT_DIR specified by chirp.common.

    :param indicators: A dict containing parsed events indicator files.
    :type indicators: dict
    """
    if not indicators:
        return
    hits = 0
    num_logs = 0
    logging.debug("Entered events plugin.")
    event_types = {indicator["indicator"]["event_type"] for indicator in indicators}
    report = {indicator["name"]: build_report(indicator) for indicator in indicators}
    run_args = [
        (event_type, indicators, report, num_logs) for event_type in event_types
    ]
    async with aiomp.Pool() as pool:
        try:
            async for i in pool.map(_run, tuple(run_args)):
                _rep = i[0]
                num_logs += i[1]
                for k, v in _rep.items():
                    try:
                        report[k]["_search_criteria"] = v["_search_criteria"]
                    except KeyError:
                        pass
                    report[k]["matches"] += v["matches"]
        except KeyboardInterrupt:
            pass

    hits = sum(len(v["matches"]) for _, v in report.items())
    logging.log(EVENTS, "Read {} logs, found {} matches.".format(num_logs, hits))
    with open(os.path.join(OUTPUT_DIR, "events.json"), "w+") as writeout:
        writeout.write(
            json.dumps({r: report[r] for r in report if report[r]["matches"]})
        )
