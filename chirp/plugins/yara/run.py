"""Provides a coroutine to run yara rules against a set of files."""

# Standard Python Libraries
from functools import lru_cache
from glob import glob
import itertools
import json
import os
import re
from typing import Any, Dict, Iterator, Tuple, Union

# cisagov Libraries
from chirp.common import CONSOLE, OS, OUTPUT_DIR, build_report

try:
    # Third-Party Libraries
    import aiomultiprocess as aiomp
    import yara

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False


def normalize_paths(path: str) -> Iterator[str]:
    """Normalize paths in the yara query.

    :param path: The path to the files being scanned.
    :type path: str
    :yield: Normalized paths.
    :rtype: Iterator[str]
    """
    if OS == "Windows" and path == "\\**":
        for letter in re.findall(
            r"[A-Z]+:.*$", os.popen("mountvol /").read(), re.MULTILINE  # nosec
        ):
            yield from normalize_paths(letter + "**")
    elif "*" in path:
        yield from [p for p in glob(path, recursive=True) if os.path.exists(p)]
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

    async def _run(args: Tuple[int, str, dict]) -> Union[Dict[str, Any], None]:
        """Handle our multiprocessing tasks."""
        count, path, indicators = args
        _indicators = [
            (indicator["name"], indicator["indicator"]["rule"])
            for indicator in indicators
        ]
        yara_rules = compile_rules(tuple(_indicators))
        ignorelist = [
            "\\OneDrive\\",
            "\\OneDriveTemp\\",
        ]  # Ignore these paths, so we don't enumerate cloud drives
        if count % 50000 == 0 and count != 0:
            CONSOLE(
                "[cyan][YARA][/cyan] We're still working on scanning files. {} processed.".format(
                    count
                )
            )
        if count == 1:
            CONSOLE("[cyan][YARA][/cyan] Beginning processing.")

        # Sometimes glob.glob gives us paths with *
        if (
            os.path.exists(path)
            and (
                path != "." and path != "\\" and all(x not in path for x in ignorelist)
            )
            and not os.path.isdir(path)
        ):
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

    async def run(indicators: dict) -> None:
        """Accept a dict containing yara indicators and write out to the OUTPUT_DIR specified by chirp.common.

        :param indicators: A NamespaceDict containing parsed yara indicator files.
        :type indicators: dict
        """
        if not indicators:
            return

        CONSOLE("[cyan][YARA][/cyan] Entered yara plugin.")

        files = [i["indicator"]["files"] for i in indicators]
        files = "\\**" if "\\**" in files else ", ".join(files)

        if files == "\\**":
            blame = [i["name"] for i in indicators if i["indicator"]["files"] == "\\**"]
            CONSOLE(
                "[cyan][YARA][/cyan] Enumerating the entire filesystem due to {}... this is going to take a while.".format(
                    blame
                )
            )

        report = {
            indicator["name"]: build_report(indicator) for indicator in indicators
        }

        hits = 0
        run_args = []

        # Normalize every path, for every path
        try:
            run_args = [
                (a, b, indicators) for a, b in enumerate(normalize_paths(files), 1)
            ]
            async with aiomp.Pool() as pool:
                try:
                    async for result in pool.map(_run, tuple(run_args)):
                        if result:
                            report[result["namespace"]]["matches"].append(result)
                            hits += 1
                except KeyboardInterrupt:
                    pass
        except IndexError:
            pass

        count = len(run_args)

        CONSOLE("[cyan][YARA][/cyan] Done. Processed {} files.".format(count))
        CONSOLE("[cyan][YARA][/cyan] Found {} hit(s) for yara indicators.".format(hits))

        with open(os.path.join(OUTPUT_DIR, "yara.json"), "w+") as writeout:
            writeout.write(
                json.dumps({r: report[r] for r in report if report[r]["matches"]})
            )


else:
    CONSOLE(
        "[red][!][/red] yara-python is a required dependency for the yara plugin. Please install yara-python with pip."
    )
    CONSOLE("[cyan][YARA][/cyan] Hit an error, exiting.")

    async def run(indicators: dict) -> None:
        """Return if there is an import error.

        :param indicators: Parsed yara indicator files.
        :type indicators: dict
        """
        return
