"""Provides methods for loading indicator files."""

# Standard Python Libraries
import logging
from typing import Iterator, List

# Third-Party Libraries
import yaml


def from_yaml(file_paths: List[str]) -> Iterator[dict]:
    """Given a list of yaml files, parses files and returns as a dict.

    :param file_paths: A list of file paths.
    :type file_paths: List[str]
    :yield: A dict representation of a yaml file.
    :rtype: Iterator[dict]
    """
    logging.debug("Started indicator loader.")
    for indicator in file_paths:
        try:
            yield from yaml.safe_load_all(open(indicator, encoding="utf8").read())
        except (TypeError, UnicodeDecodeError):
            logging.critical("Had an issue parsing {}".format(indicator))
    logging.debug("Finished loading indicators.")
