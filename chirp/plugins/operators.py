"""An operators module used by plugins for simple operator, operand queries on their data."""

# Standard Python Libraries
from functools import lru_cache
import logging
import re
from typing import Any, Callable, Dict, List, Tuple, Union


@lru_cache(maxsize=128)
def OPERATOR_MAP(symbol: str) -> Union[Callable, None]:
    """Map a string to a function for an operator.

    :param symbol: The symbol for an operator.
    :type symbol: str
    :return: The function related to the symbol.
    :rtype: Callable
    """
    d = {
        "==": equals,
        "!=": notequals,
        "~=": regular_expression,
    }
    try:
        return d[symbol]
    except KeyError:
        logging.error("(OPERATORS) Unknown symbol '{}'.".format(symbol))


def navigate_structure(item: Dict[str, Any], keys: List[str] = []) -> Any:
    """Enumerate a nested dictionary to grab a subkey given a list of keys to traverse.

    :param item: The nested dictionary.
    :type item: Dict[str, Any]
    :param keys: Keys to traverse., defaults to []
    :type keys: List[str], optional
    :return: The data at the given location.
    :rtype: Union[Dict[str, Any], None]
    """
    try:
        if keys:
            item = item[keys.pop(0)]
            return navigate_structure(item, keys)
        else:
            return item
    except KeyError:
        return None


def parse_operator_and_operand(search_string: str) -> Union[Tuple[Any, Any], None]:
    """Parse a string in the format of "operator operand" and returns the callable and operand string.

    :param search_string: The search string to parse.
    :type search_string: str
    :return: The operator callable and operand parsed from the search string.
    :rtype: Union[Tuple[Any, Any], None]
    """
    NONE_TYPES = ["None", "none", "null", "''", '""', "NULL"]
    try:
        s = search_string.split(" ")
    except AttributeError:
        logging.error(
            "(OPERATORS) search string '{}' appears to be the wrong data type.".format(
                search_string
            )
        )
        return
    try:
        operator = OPERATOR_MAP(s[0])
        operand = " ".join(s[1:])
    except IndexError:
        logging.error(
            "(OPERATORS) Did not receive a parseable string! '{}'".format(search_string)
        )
        return
    if operand in NONE_TYPES:
        operand = ""
    return (operator, operand)


def equals(check_value: Any, item: Any) -> bool:
    """Check if two values are equal.

    :param check_value: Value to check.
    :type check_value: Any
    :param item: Item to check against.
    :type item: Any
    :return: Bool of comparison.
    :rtype: bool
    """
    return check_value == item


def notequals(check_value: Any, item: Any) -> bool:
    """Check if two values are not equal.

    :param check_value: Value to check.
    :type check_value: Any
    :param item: Item to check against.
    :type item: Any
    :return: Bool of comparison.
    :rtype: bool
    """
    return not equals(check_value, item)


def regular_expression(check_value: Any, item: Any) -> bool:
    """Run a regular expression search given a regex and item to search.

    :param check_value: Regular expression.
    :type check_value: Any
    :param item: Item to search against.
    :type item: Any
    :return: Bool of comparison.
    :rtype: bool
    """
    return bool(re.search(check_value, str(item)))


def searcher(check_value: Any, item: Any, key: Any = None) -> Union[bool, None]:
    """Search a given item, given a check value and optionally a key.

    :param check_value: A value to search for.
    :type check_value: Any
    :param item: An item to search against.
    :type item: Any
    :param key: An optional key to use to drill into data., defaults to None
    :type key: Any, optional
    :return: A boolean value of the match or None if there is an error.
    :rtype: Union[bool, None]
    """
    parsed = parse_operator_and_operand(check_value)
    if parsed:
        operator, operand = parsed
        if key and "." in key:
            search_item = navigate_structure(item, key.split("."))
            return searcher(check_value, search_item, None)
        elif isinstance(item, dict):
            for _, v in item.items():
                if not searcher(check_value, v, key):
                    continue
                else:
                    return True
        else:
            return operator(operand, item)
