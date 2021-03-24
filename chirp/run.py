"""The main engine for CHIRP. Enumerates and runs the relevant plugin coroutines."""

# Standard Python Libraries
import asyncio
import os
from typing import Callable, Dict, Iterable, Iterator, List

# cisagov Libraries
from chirp import load
from chirp.common import CRITICAL, DEBUG, ERROR, OUTPUT_DIR, PLUGINS
from chirp.plugins import events, loader, network, registry, yara  # noqa: F401


def run() -> None:
    """Run plugins and write out output."""
    if not os.path.exists(OUTPUT_DIR):
        os.mkdir(OUTPUT_DIR)
    loaded_plugins = loader.load(PLUGINS)
    run_plugins(loaded_plugins)


def run_plugins(plugins: Dict[str, Callable]) -> None:
    """Call our async method.

    :param plugins: A dictionary with the name of a plugin as the key and its entrypoint as the value.
    :type plugins: Dict[str, Callable]
    """
    _loop = asyncio.get_event_loop()
    _loop.run_until_complete(_run_coroutines(plugins))


async def _run_coroutines(plugins: Dict[str, Callable]) -> None:
    """Run our plugin coroutines.

    :param plugins: A dictionary with the name of a plugin as the key and its entrypoint as the value.
    :type plugins: Dict[str, Callable]
    """
    _indicators = list(
        check_valid_indicator_types(
            load.from_yaml(get_indicators()), list(plugins.keys())
        )
    )
    await asyncio.gather(
        *[
            entrypoint(
                [
                    indicator
                    for indicator in _indicators
                    if indicator["ioc_type"] == plugin
                ]
            )
            for plugin, entrypoint in plugins.items()
        ]  # Run entrypoint for each plugin, passing indicators for that plugin
    )


def check_valid_indicator_types(
    indicator_generator: Iterable[dict], plugins: List[str]
) -> Iterator[dict]:
    """Check that an indicator file has a matching plugin and if so yields the indicator.

    :param indicator_generator: A generator to yield parsed indicator files.
    :type indicator_generator: Iterable[dict]
    :param plugins: Names of valid plugins.
    :type plugins: List[str]
    :yield: Valid parsed indicators.
    :rtype: Iterator[dict]
    """
    failed_types = []
    for indicator in indicator_generator:
        if indicator["ioc_type"] in plugins:
            yield indicator
            DEBUG("Loaded {}".format(indicator["name"]))
        else:
            if (indicator["ioc_type"] in plugins or "all" in plugins) and indicator[
                "ioc_type"
            ] not in failed_types:
                ERROR(
                    """Can't locate plugin "{}". It is possible it has not loaded due to an error.""".format(
                        indicator["ioc_type"]
                    )
                )
            failed_types.append(indicator["ioc_type"])
            continue


def get_indicators() -> Iterator[str]:
    """Yield paths to indicators.

    :yield: A path to an indicator file.
    :rtype: Iterator[str]
    """
    try:
        for f in os.listdir("indicators"):
            if "README" not in f and f.split(".")[-1] in ("yaml", "yml"):
                yield os.path.join("indicators", f)
    except FileNotFoundError:
        CRITICAL(
            "Could not find an indicators directory. Indicators should be in the same directory as this executable."
        )
