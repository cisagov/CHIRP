"""Common constants and methods for CHIRP."""

# Standard Python Libraries
import argparse
import ctypes
import os
import queue
import sys
import threading
import typing as t

# Third-Party Libraries
from rich.console import Console
from rich.traceback import install

parser = argparse.ArgumentParser(
    prog="CHIRP",
    description="CHIRP. A Window host forensic artifact collection tool.",
)
parser.add_argument(
    "-o", "--output", help="Specified output directory.", default="output"
)
parser.add_argument(
    "-l",
    "--log-level",
    help="Log level. Info, Error, Critical, or Debug.",
    default="silent",
)
parser.add_argument(
    "-p", "--plugins", nargs="*", help="Specified plugins to run.", default="all"
)
ARGS, _ = parser.parse_known_args()
OUTPUT_DIR = ARGS.output
PLUGINS = ARGS.plugins


def _sinkhole(*args, **kwargs) -> None:
    """Drop any input and return nothing."""
    pass


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


_CONSOLE = Console(record=True)

_console_queue = queue.Queue()

CONSOLE = lambda x: _console_queue.put(x)
_INFO = lambda x: _console_queue.put("[green][+][/green] {}".format(x))
_ERROR = lambda x: _console_queue.put("[red][-][/red] {}".format(x))
_CRITICAL = lambda x: _console_queue.put("[cyan][!][/cyan] {}".format(x))
_DEBUG = lambda x: _console_queue.put("[yellow][?][/yellow] {}".format(x))

"""
A workaround to log levels, gives us greater control in the main program.
This mapping allows the user to specify a log level (debug, critical, error, info, silent).
Based on the user input, functions are returned matching the desired output,
sinkhole() is as it sounds, a method to capture input and output nothing,
which effectively allows us to void calls like ERROR("some error text") as
sinkhole will capture the input and return None.
"""
log_levels = {
    "debug": [_INFO, _ERROR, _CRITICAL, _DEBUG],
    "critical": [_INFO, _ERROR, _CRITICAL, _sinkhole],
    "error": [_INFO, _ERROR, _sinkhole, _sinkhole],
    "info": [_INFO, _sinkhole, _sinkhole, _sinkhole],
    "silent": [_sinkhole, _sinkhole, _sinkhole, _sinkhole],
}

INFO, ERROR, CRITICAL, DEBUG = log_levels[ARGS.log_level.lower()]

# https://github.com/python/typing/issues/182
JSON = t.Union[str, int, float, bool, None, t.Mapping[str, "JSON"], t.List["JSON"]]

ADMIN = _is_admin()
OS = _get_platform()

# Install traceback handler
install()


def _logger():
    """Use a queue to prevent async functions from writing to the console at the same time. Sleep for 2 seconds then checks if there is data to write out."""
    if _console_queue:
        while not _console_queue.empty():
            _CONSOLE.log(_console_queue.get())
    _thread = threading.Timer(interval=2, function=_logger)
    _thread.daemon = True
    _thread.start()


_logger()


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
