"""Module to load plugins from a 'plugins' directory."""

# Standard Python Libraries
import importlib
import pkgutil
from typing import Callable, Dict, List

# cisagov Libraries
from chirp.common import ADMIN, DEBUG, ERROR, INFO, OS


def _parse_name(plugin: Callable) -> str:
    """Parse the name of a plugin by grabbing the last value from the __name__.split(".")."""
    return plugin.__name__.split(".")[-1]


def _verify_privilege(plugin: Callable) -> bool:
    """Verify proper privilege for plugin."""
    try:
        admin = plugin.REQUIRED_ADMIN
        if ADMIN or not admin:
            INFO("Loaded {}".format(_parse_name(plugin)))
            return True
        else:
            ERROR("{} must be ran from an admin console.".format(_parse_name(plugin)))
            return False
    except AttributeError:
        INFO("Loaded {}".format(_parse_name(plugin)))
        return True


def _str_load(
    name: str, pkg: Callable, discovered_plugins: Dict[str, Callable]
) -> None:
    """Load a plugin given the REQUIRED_OS attribute is a string."""
    if OS.lower() in pkg.REQUIRED_OS.lower():
        if _verify_privilege(pkg):
            discovered_plugins[name] = pkg.entrypoint
    else:
        ERROR("{} must be ran on {}".format(name, pkg.REQUIRED_OS))


def _iter_load(
    name: str, pkg: Callable, discovered_plugins: Dict[str, Callable]
) -> None:
    """Load a plugin given the REQUIRED_OS attribute is a list or tuple."""
    if any(
        OS.lower() in operating_system.lower() for operating_system in pkg.REQUIRED_OS
    ):
        if _verify_privilege(pkg):
            discovered_plugins[name] = pkg.entrypoint
    else:
        ERROR("{} must be ran on {}".format(name, " or ".join(pkg.REQUIRED_OS)))


def _loader(name: str, discovered_plugins: Dict[str, Callable]) -> None:
    """Load discovered plugins in the ./plugins directory."""
    INFO("Found {}".format(name))
    pkg = importlib.import_module("chirp.plugins.{}".format(name))
    try:
        if not hasattr(pkg.entrypoint, "__call__"):
            raise AttributeError
        try:
            if isinstance(pkg.REQUIRED_OS, str):
                _str_load(name, pkg, discovered_plugins)
            elif isinstance(pkg.REQUIRED_OS, (tuple, list)):
                _iter_load(name, pkg, discovered_plugins)
            else:
                ERROR(
                    "Not sure how to interpret REQUIRED_OS for plugin {}".format(name)
                )
        except AttributeError:
            if _verify_privilege(pkg):
                discovered_plugins[name] = pkg.entrypoint
    except AttributeError:
        ERROR("{} does not have a valid entrypoint".format(name))


def load(plugins: List[str]) -> Dict[str, Callable]:
    """Load plugins discovered in the plugins directory.

    :return: A dictionary with a key of the plugin name and a value of the entrypoint.
    :rtype: Dict[str, Callable]
    """
    DEBUG("Starting plugin loader. Loading plugins: {}".format(plugins))
    discovered_plugins = {}
    for _, name, ispkg in pkgutil.iter_modules(path=["chirp/plugins"]):
        if ispkg and ((name in plugins) or ("all" in plugins)):
            _loader(name, discovered_plugins)
    DEBUG("Finished loading plugins.")
    return discovered_plugins
