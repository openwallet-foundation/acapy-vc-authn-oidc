"""
This file contains VariableSubstitutionMap class, which provides a mapping of
static variables that can be used in a proof.
Other users of this project can add their own variable substitutions or override
the entire file to suit their own needs.
"""

import copy
import re
import time
from datetime import datetime, timedelta

import structlog
from typing_extensions import Callable

from ..core.config import settings

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

SubstitutionFunction = Callable[..., int | str]


class VariableSubstitutionMap:
    def __init__(self):
        # Map of static variables that can be used in a proof
        # This class defines threshold_years_X as a dynamic one
        self.static_map = {
            "$now": self.get_now,
            "$today_int": self.get_today_date,
            "$tomorrow_int": self.get_tomorrow_date,
        }

        self.user_static_map: dict[re.Pattern[str], SubstitutionFunction] = {
            re.compile(r"\$threshold_years_(\d+)"): self.get_threshold_years_date
        }

    def add_variable_substitution(
        self, pattern: str, substitution_function: SubstitutionFunction
    ):
        """Takes a valid regular expression PATTERN and a function
        who's arguments correspond with each regex group
        SUBSTITUTION_FUNCTION. Each captured regex group will be
        passed to the function as a str.

        Examples:
        vsm.add_variable_substitution(r\"\\$years since (\\d+) (\\d+)\", lambda x, y: int(x) + int(y))
        vsm[f"$years since {10} {12}"] => 22
        """
        self.user_static_map[re.compile(pattern)] = substitution_function

    def get_threshold_years_date(self, years: str) -> int:
        """
        Calculate the threshold date for a given number of years.

        Args:
            years (int): The number of years to subtract from the current year.

        Returns:
            int: The current date minux X years in YYYYMMDD format.
        """
        threshold_date = datetime.today().replace(
            year=datetime.today().year - int(years)
        )
        return int(threshold_date.strftime("%Y%m%d"))

    def get_now(self) -> int:
        """
        Get the current timestamp.

        Returns:
            int: The current timestamp in seconds since the epoch.
        """
        return int(time.time())

    def get_today_date(self) -> int:
        """
        Get today's date in YYYYMMDD format as a number.

        Returns:
            int: Today's date in YYYYMMDD format.
        """
        return int(datetime.today().strftime("%Y%m%d"))

    def get_tomorrow_date(self) -> int:
        """
        Get tomorrow's date in YYYYMMDD format as a number.

        Returns:
            int: Tomorrow's date in YYYYMMDD format.
        """
        return int((datetime.today() + timedelta(days=1)).strftime("%Y%m%d"))

    # For "dynamic" variables, use a regex to match the key and return a lambda function
    # So a proof request can use $threshold_years_X to get the years back for X years
    def __contains__(self, key: str) -> bool:
        res = key in self.static_map
        if not res:
            for i in self.user_static_map.keys():
                if re.match(i, key):
                    return True
        return res

    def __getitem__(self, key: str):
        if key in self.static_map:
            return self.static_map[key]
        for i, j in self.user_static_map.items():
            if nmatch := re.match(i, key):
                return lambda: j(*nmatch.groups())
        raise KeyError(f"Key {key} not found in format_args_function_map")


# Create an instance of the custom mapping class
variable_substitution_map = VariableSubstitutionMap()


def apply_user_variables():
    try:
        with open(settings.CONTROLLER_VARIABLE_SUBSTITUTION_OVERRIDE) as user_file:
            code = user_file.read()
    except TypeError:
        logger.warning("No user defined variable substitutions file provided")
        return None
    except FileNotFoundError:
        logger.warning("User defined variable substitutions file could not be found")
        return None
    else:
        og_substitution_map = copy.copy(variable_substitution_map.user_static_map)
        exec(code)
        if len(variable_substitution_map.user_static_map) <= 1:
            logger.info("No new user created variable substitution where found")

        for pattern, func in variable_substitution_map.user_static_map.items():
            if pattern not in og_substitution_map:
                logger.info(
                    f'New user created variable substitution: The pattern "{pattern.pattern}" is now mapped to the function {func.__name__}'
                )


apply_user_variables()
