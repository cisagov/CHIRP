"""Provides a coroutine to run yara rules against a set of files."""

# Standard Python Libraries
from functools import lru_cache, partial
from glob import iglob
import hashlib
import itertools
import json
import logging
from multiprocessing import Pool
import os
import signal
import string
from typing import Any, Dict, Iterator, List, Tuple, Union

# cisagov Libraries
from chirp.common import OS, OUTPUT_DIR, TARGETS, YARA, build_report

try:
    # Third-Party Libraries
    import yara

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False

if OS == "Windows":
    # Standard Python Libraries
    from ctypes import windll


def _unicode_handler(file_path):
    try:
        if isinstance(file_path, bytes):
            return file_path.decode(encoding="utf8")
        elif isinstance(file_path, str):
            return file_path.encode(encoding="utf8")
        else:
            logging.error("Unicode handler received incorrect file type.")
            return "???"
    except UnicodeError:
        return _unicode_handler(os.path.dirname(file_path))


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


def normalize_paths(path: str) -> Iterator[str]:
    """Normalize paths in the yara query.

    :param path: The path to the files being scanned.
    :type path: str
    :yield: Normalized paths.
    :rtype: Iterator[str]
    """
    if OS == "Windows" and path == "\\**":
        for letter in _get_drives():
            yield from normalize_paths(letter + ":\\**")
    elif "*" in path:
        yield from iglob(path, recursive=True)
    if "," in path:
        yield from list(
            itertools.chain.from_iterable(
                [(normalize_paths(p.strip())) for p in path.split(",")]
            )
        )
    else:
        yield os.path.abspath(path)


if HAS_LIBS:

    @lru_cache(maxsize=128)
    def compile_rules(indicators: Tuple[str, str]) -> yara.Rules:
        """Compile yara rules to be ran.

        :param indicators: Parsed yara indicator files.
        :type indicators: dict
        :return: A compilation of yara rules.
        :rtype: yara.Rules
        """
        return yara.compile(sources=dict(indicators))

    def _sha256(filepath):
        try:
            return hashlib.sha256(
                "".join(
                    x.rstrip() for x in open(filepath, "r", encoding="utf8").readlines()
                ).encode()
            ).hexdigest()
        except (PermissionError, UnicodeError):
            return None

    def _generate_hashes(path="./indicators/*"):
        return (_sha256(f) for f in iglob(path))

    HASHES = list(_generate_hashes())

    def _compare_hash(path):
        try:
            return _sha256(path) in HASHES
        except MemoryError:
            return False

    def _run(indicators, count_path) -> Union[Dict[str, Any], None]:
        """Handle our multiprocessing tasks."""
        count, path = count_path
        if count == 1:
            logging.log(YARA, "Beginning processing.")
        elif count % 50000 == 0:
            logging.log(
                YARA,
                "We're still working on scanning files. {} processed.".format(count),
            )
        if os.path.exists(path) and not os.path.isdir(path) and not _compare_hash(path):
            _indicators = [
                (indicator["name"], indicator["indicator"]["rule"])
                for indicator in indicators
            ]
            yara_rules = compile_rules(tuple(_indicators))

            try:
                matches = yara_rules.match(path)
                if matches:
                    for match in matches:
                        attrs = ["meta", "namespace", "rule", "strings", "tags"]
                        match_dict = {k: str(getattr(match, k)) for k in attrs}
                        match_dict["file"] = path
                        return match_dict
            except yara.Error:
                pass
            except UnicodeError:
                logging.error(
                    "Unicode error in {} file or directory. May require manual investigation.".format(
                        _unicode_handler(path)
                    )
                )

    def _signal_handler():
        """Handle keyboard interrupts received during multiprocessing.

        Reference: `John Reese <https://jreese.sh/blog/python-multiprocessing-keyboardinterrupt>`_
        """
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    async def run(indicators: dict) -> None:
        """Accept a dict containing yara indicators and write out to the OUTPUT_DIR specified by chirp.common.

        :param indicators: A NamespaceDict containing parsed yara indicator files.
        :type indicators: dict
        """
        if not indicators:
            return

        logging.info("Entered yara plugin.")

        files = (
            [i["indicator"]["files"] for i in indicators] if not TARGETS else TARGETS
        )
        files = "\\**" if "\\**" in files else ", ".join(files)

        logging.info("Yara targets: {}".format(files))

        if files == "\\**":
            blame = [i["name"] for i in indicators if i["indicator"]["files"] == "\\**"]
            logging.log(
                YARA,
                "Enumerating the entire filesystem due to {}... this is going to take a while.".format(
                    blame
                ),
            )

        report = {
            indicator["name"]: build_report(indicator) for indicator in indicators
        }

        hits = 0
        count = 0

        # Normalize every path, for every path
        try:
            with Pool(initializer=_signal_handler) as pool:
                for result in pool.imap_unordered(
                    partial(_run, indicators),
                    enumerate(normalize_paths(files), 1),
                    chunksize=1000,
                ):
                    if result:
                        report[result["namespace"]]["matches"].append(result)
                        hits += 1
                    count += 1
        except IndexError:
            pass
        except KeyboardInterrupt:
            logging.log(YARA, "Received a keyboard interrupt. Killing workers.")

        logging.log(YARA, "Done. Processed {} files.".format(count))
        logging.log(YARA, "Found {} hit(s) for yara indicators.".format(hits))

        with open(os.path.join(OUTPUT_DIR, "yara.json"), "w+") as writeout:
            writeout.write(
                json.dumps({r: report[r] for r in report if report[r]["matches"]})
            )


else:
    logging.error(
        "yara-python is a required dependency for the yara plugin. Please install yara-python with pip."
    )
    logging.error("Hit an error, exiting.")

    async def run(indicators: dict) -> None:
        """Return if there is an import error.

        :param indicators: Parsed yara indicator files.
        :type indicators: dict
        """
        return
