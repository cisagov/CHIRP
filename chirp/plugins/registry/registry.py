"""Provides methods for parsing and retrieving registry entries."""

# Standard Python Libraries
import logging
from typing import Iterator, Tuple

# cisagov Libraries
from chirp.common import REGISTRY

HAS_LIBS = False
try:
    # Standard Python Libraries
    import winreg

    HAS_LIBS = True
except ImportError:
    pass

if HAS_LIBS:

    def _build_keys() -> dict:
        """Create a mapping of key names to their winreg constants."""
        keys = {}
        key_names = [
            "HKEY_LOCAL_MACHINE",
            "HKEY_CLASSES_ROOT",
            "HKEY_CURRENT_USER",
            "HKEY_USERS",
            "HKEY_PERFORMANCE_DATA",
            "HKEY_CURRENT_CONFIG",
            "HKEY_DYN_DATA",
        ]
        for key_name in key_names:
            abbrv = "HK" + "".join([k[0] for k in key_name.split("_")][1:])
            keys[key_name] = getattr(winreg, key_name)
            keys[abbrv] = getattr(winreg, key_name)
        return keys

    def _build_value_map() -> dict:
        """Create a mapping of winreg constants to their string representations."""
        values = [
            "REG_BINARY",
            "REG_DWORD",
            "REG_DWORD_LITTLE_ENDIAN",
            "REG_DWORD_BIG_ENDIAN",
            "REG_EXPAND_SZ",
            "REG_LINK",
            "REG_MULTI_SZ",
            "REG_NONE",
            "REG_QWORD",
            "REG_QWORD_LITTLE_ENDIAN",
            "REG_RESOURCE_LIST",
            "REG_FULL_RESOURCE_DESCRIPTOR",
            "REG_RESOURCE_REQUIREMENTS_LIST",
            "REG_SZ",
        ]
        return {getattr(winreg, value): value for value in values}

    REGISTRIES = _build_keys()
    REGISTRY_VALUE_TYPES = _build_value_map()

    def _normalize_key(hkey: str) -> Tuple[int, str]:
        """Normalize a key to the hive and key."""
        key = r"{}".format(hkey)
        registry = key.split("\\")[0].strip(":").strip("b'")
        try:
            hive = _build_keys()[registry]
        except KeyError:
            return 0, ""
        normalized_key = "\\".join(key.split("\\")[1:])
        return hive, normalized_key

    async def enumerate_registry_values(hkey: str) -> Iterator[dict]:
        """Enumerate the values of the given key.

        :param hkey: A registry key to enumerate
        :type hkey: str
        :yield: Registry key values
        :rtype: Iterator[dict]
        """
        hive, key = _normalize_key(hkey)
        if not hive or not key:
            logging.log(REGISTRY, "Unable to read key '{}'".format(hkey))
            return
        registry = winreg.ConnectRegistry(None, hive)
        try:
            with winreg.OpenKey(registry, key) as registry_key:
                for i in range(winreg.QueryInfoKey(registry_key)[1]):
                    value_tuple = winreg.EnumValue(registry_key, i)
                    yield {
                        "key": value_tuple[0],
                        "value": value_tuple[1],
                        "registry_type": REGISTRY_VALUE_TYPES[value_tuple[2]],
                    }
        except FileNotFoundError:
            logging.log(REGISTRY, "Key {} does not exist.".format(hkey))


else:

    async def enumerate_registry_values(hkey: str) -> Iterator[str]:
        """Return if the proper libraries can't be imported (like wrong OS).

        :param hkey: A registry key to query
        :type hkey: str
        :yield: Literally "ERROR"
        :rtype: Iterator[str]
        """
        logging.log(REGISTRY, "Registry plugin is only compatible with Windows.")
        yield "ERROR"
