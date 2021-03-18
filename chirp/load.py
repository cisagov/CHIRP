"""Provides methods for loading indicator files."""

# Standard Python Libraries
from typing import Iterator, List

# Third-Party Libraries
import yaml

# cisagov Libraries
from chirp.common import CRITICAL, DEBUG


def from_yaml(file_paths: List[str]) -> Iterator[dict]:
    """Given a list of yaml files, parses files and returns as a dict.

    :param file_paths: A list of file paths.
    :type file_paths: List[str]
    :yield: A dict representation of a yaml file.
    :rtype: Iterator[dict]
    """
    DEBUG("Started indicator loader.")
    for indicator in file_paths:
        try:
            yield from yaml.safe_load_all(open(indicator, encoding="utf8").read())
        except (TypeError, UnicodeDecodeError):
            CRITICAL("Had an issue parsing {}".format(indicator))
    DEBUG("Finished loading indicators.")
