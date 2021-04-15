"""Generates usable dictionaries from event log data."""

# Standard Python Libraries
from functools import lru_cache
import logging
import os
from pathlib import Path
import re
import string
import sys
from typing import Any, Dict, Iterator, List, Union

# cisagov Libraries
from chirp.common import EVENTS, JSON, OS

HAS_LIBS = False
try:
    # cisagov Libraries
    from chirp.plugins.events.evtx2json import iter_evtx2xml, splunkify, xml2json

    HAS_LIBS = True
except ImportError:
    logging.error(
        "(EVENTS) python-evtx, dict-toolbox, and xmljson are required dependencies for the events plugin. Please install requirements with pip."
    )

if OS == "Windows":
    # Standard Python Libraries
    from ctypes import windll

PATH = Path(sys.executable)


def _get_drives() -> List[str]:
    """
    Return a list of valid drives.

    Reference: `RichieHindle, StackOverflow <https://stackoverflow.com/a/827398>`_
    """
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(letter)
        bitmask >>= 1

    return drives


def _path_iterator():
    """Iterate over possible winevt paths to find valid winevts."""
    if OS == "Windows":
        dirs = ("Sysnative", "System32")
        for letter in _get_drives():
            for d in dirs:
                if os.path.exists(letter + ":\\Windows\\{}\\winevt\\Logs".format(d)):
                    return (
                        letter + ":\\Windows\\{}\\winevt\\Logs\\".format(d) + "{}.evtx"
                    )
    return None


default_dir = _path_iterator()

if not default_dir:
    if OS == "Windows":
        logging.log(EVENTS, "We can't find windows event logs at their standard path.")
    HAS_LIBS = False


if HAS_LIBS:

    @lru_cache(maxsize=128)
    def _no_camels(word: str) -> str:
        """Take a CamelCase string and returns the snake_case equivalent.

        Reference: `Stack Overflow <https://stackoverflow.com/a/1176023>`_
        """
        new_word = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", word)
        return re.sub("([a-z0-9])([A-Z])", r"\1_\2", new_word).lower().strip("@_")

    # Leverages evtx2json, written by @vavarachen to parse event logs into JSON data.
    # https://github.com/vavarachen/evtx2json << We had to copy the file to our repo because it's not in PYPI
    # This library in turn leverages python-evtx written by @williballenthin
    # https://github.com/williballenthin/python-evtx
    def process_files(evtx_file: str) -> Iterator[JSON]:
        """Process a given evtx file, yields a JSON representation of the data.

        :param evtx_file: The literal path to the evtx file.
        :type evtx_file: str
        :yield: JSON formatted representation of an event log.
        :rtype: Iterator[JSON]
        """
        if os.path.exists(evtx_file):
            for xml_str in iter_evtx2xml(evtx_file):
                try:
                    yield splunkify(xml2json(xml_str), source=evtx_file)
                except:  # noqa: E722
                    pass

    def t_dict(d: Union[List, Dict]) -> Union[Dict, List]:
        """Given a dictionary, converts the CamelCase keys to snake_case.

        :param d: A dictionary to format.
        :type d: Union[List, Dict]
        :return: A properly formatted dict with snake_case keys.
        :rtype: Union[Dict,List]

        Reference: `Stack Overflow <https://stackoverflow.com/questions/60148175/convert-camelcase-to-snakecase>_`
        """
        if isinstance(d, list):
            return [t_dict(i) if isinstance(i, (dict, list)) else i for i in d]
        return {
            _no_camels(a): t_dict(b) if isinstance(b, (dict, list)) else b
            for a, b in d.items()
        }

    async def gather(event_type: str) -> Iterator[Dict]:
        """Yield or "gather" event logs given an event type. Ex: "Application" will read from Application.evtx.

        :param event_type: An event log to read from.
        :type event_type: str
        :yield: Parsed and formatted eventlog data.
        :rtype: Iterator[Dict]
        """
        for item in process_files(default_dir.format(event_type)):
            yield t_dict(item)


else:

    async def gather(*args: Any, **kwargs: Any) -> Iterator[str]:
        """Return if there is an import error. Allows us to gracefully handle import errors.str.

        :yield: The literal string "ERROR"
        :rtype: Iterator[str]
        """
        yield "ERROR"
