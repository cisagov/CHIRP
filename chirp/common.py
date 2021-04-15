"""Common constants and methods for CHIRP."""

# Standard Python Libraries
import argparse
import ctypes
import glob
import json
import logging
import os
import sys
import typing as t

# Third-Party Libraries
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

parser = argparse.ArgumentParser(
    prog="CHIRP",
    description="CHIRP. A Window host forensic artifact collection tool.",
)
parser.add_argument("-a", "--activity", help="Specified AA threat package to run.")
parser.add_argument(
    "-o", "--output", help="Specified output directory.", default="output"
)
parser.add_argument(
    "-p", "--plugins", nargs="*", help="Specified plugins to run.", default="all"
)
parser.add_argument(
    "-t",
    "--targets",
    nargs="*",
    help="Specified override filepath targets for yara plugin indicators.",
    default=None,
)
parser.add_argument(
    "--non-interactive",
    help="Run in non-interactive mode (close after completion).",
    action="store_true",
)
parser.add_argument(
    "--silent",
    help="Silence CHIRP output.",
    action="store_true",
)
parser.add_argument(
    "-v",
    "--verbose",
    action="count",
    default=0,
    help="program verbosity, use more `v`s to increase verbosity, default is no verbosity.",
)
ARGS, _ = parser.parse_known_args()
OUTPUT_DIR = ARGS.output
PLUGINS = ARGS.plugins
TARGETS = ARGS.targets
ACTIVITY = ARGS.activity
NON_INTERACTIVE = ARGS.non_interactive

if ARGS.verbose >= 2:
    LOG_LEVEL = logging.NOTSET
elif ARGS.verbose == 1:
    LOG_LEVEL = logging.INFO
elif NON_INTERACTIVE:
    LOG_LEVEL = 70
else:
    LOG_LEVEL = logging.ERROR

if ARGS.silent:
    LOG_LEVEL = 100

_CONSOLE = Console(
    record=True,
    theme=Theme(
        {
            "logging.level.registry": "bright_green",
            "logging.level.events": "bright_blue",
            "logging.level.yara": "bright_yellow",
            "logging.level.network": "bright_white",
            "logging.level.complete": "bright_cyan",
        }
    ),
)

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(message)s",
    datefmt="%X",
    handlers=[
        RichHandler(rich_tracebacks=True, tracebacks_show_locals=True, console=_CONSOLE)
    ],
)

EVENTS = 60
REGISTRY = 61
YARA = 62
NETWORK = 63
COMPLETE = 70

logging.addLevelName(EVENTS, "EVENTS")
logging.addLevelName(REGISTRY, "REGISTRY")
logging.addLevelName(YARA, "YARA")
logging.addLevelName(NETWORK, "NETWORK")
logging.addLevelName(COMPLETE, "COMPLETE")


def _is_admin():
    """Return True if program is ran from admin terminal.

    Reference: `Racoon.ninja <https://raccoon.ninja/en/dev/using-python-to-check-if-the-application-is-running-as-an-administrator/>`_
    """
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin


def _get_platform():
    """Return a normalized platform name."""
    if sys.platform == "darwin":
        return "MacOS"
    elif "win" in sys.platform:
        return "Windows"
    elif sys.platform == "linux":
        return "Linux"
    else:
        return "UNSUPPORTED"


# https://github.com/python/typing/issues/182
JSON = t.Union[str, int, float, bool, None, t.Mapping[str, "JSON"], t.List["JSON"]]

ADMIN = _is_admin()
OS = _get_platform()


def build_report(indicator: dict) -> dict:
    """Build a basic JSONable report format based on an indicator input.

    :param indicator: A parsed indicator file represented as a dict
    :type indicator: dict
    :return: A basic JSONable report format.
    :rtype: dict
    """
    report = {attr: indicator[attr] for attr in ["description", "confidence"]}
    report["matches"] = []
    return report


def save_log() -> None:
    """Save the log output to `chirp.log`."""
    _CONSOLE.save_text("chirp.log")


def wait() -> None:
    """
    Wait for a keypress to continue.

    Reference: `CrouZ, StackOverflow <https://stackoverflow.com/a/16933120>`_
    """
    if not ARGS.non_interactive:
        if OS == "Windows":
            os.system("pause")  # nosec
        else:
            os.system('read -s -n 1 -p "Press any key to continue..."')  # nosec
            print()


def iocs_discovered() -> bool:
    """Determine whether iocs were discovered."""
    report_files = glob.glob("{}/*".format(OUTPUT_DIR))
    for report_file in report_files:
        with open(report_file, "r") as f:
            data = json.load(f)
            if len(data) > 0:
                logging.log(
                    COMPLETE,
                    "Discovered IoCs, please see output reports for more details.",
                )
                return True
    logging.log(COMPLETE, "No IoCs discovered!")
    return False
