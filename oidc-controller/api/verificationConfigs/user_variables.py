"""Load the user defined variable substitutions file at startup."""

import copy
import re
import time
from collections.abc import Callable
from datetime import datetime, timedelta

import structlog

from ..core.config import settings
from . import variableSubstitutions
from .variableSubstitutions import variable_substitution_map

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


def _user_namespace() -> dict[str, object]:
    # Override files used to run inside variableSubstitutions.py and could use
    # its imports without importing them, so keep those names available.
    return {
        "__name__": "user_variable_substitutions",
        "copy": copy,
        "re": re,
        "time": time,
        "Callable": Callable,
        "datetime": datetime,
        "timedelta": timedelta,
        "structlog": structlog,
        "settings": settings,
        "logger": logger,
        "SubstitutionFunction": variableSubstitutions.SubstitutionFunction,
        "VariableSubstitutionMap": variableSubstitutions.VariableSubstitutionMap,
        "variable_substitution_map": variable_substitution_map,
    }


def apply_user_variables(path: str | None) -> None:
    if path is None:
        logger.warning("No user defined variable substitutions file provided")
        return
    try:
        with open(path) as user_file:
            code = user_file.read()
    except FileNotFoundError:
        logger.warning("User defined variable substitutions file could not be found")
        return

    og_substitution_map = copy.copy(variable_substitution_map.user_static_map)
    # One dict for globals and locals, so functions in the file can see the
    # file's own imports.
    exec(code, _user_namespace())
    if not variable_substitution_map.user_static_map:
        logger.info("No new user created variable substitution where found")

    for pattern, func in variable_substitution_map.user_static_map.items():
        if pattern not in og_substitution_map:
            logger.info(
                f'New user created variable substitution: The pattern "{pattern.pattern}" is now mapped to the function {func.__name__}'
            )


def load_user_variables() -> None:
    apply_user_variables(settings.CONTROLLER_VARIABLE_SUBSTITUTION_OVERRIDE)
