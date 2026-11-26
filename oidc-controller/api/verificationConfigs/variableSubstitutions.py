"""
This file contains VariableSubstitutionMap class, which provides a mapping of
static variables that can be used in a proof.
Other users of this project can add their own variable substitutions or override
the entire file to suit their own needs.
"""

import re
from collections.abc import Callable
from datetime import datetime, timedelta

SubstitutionFunction = Callable[..., int | str]


class VariableSubstitutionMap:
    def __init__(self):
        # Built-in variables. They are computed from the time passed to resolve()
        # so the result does not depend on when the function happens to run.
        self.static_map: dict[str, Callable[[datetime], int]] = {
            "$now": self.get_now,
            "$today_int": self.get_today_date,
            "$tomorrow_int": self.get_tomorrow_date,
        }
        # Built-in variables with regex groups, so $threshold_years_X works for any X.
        self.dynamic_map: dict[re.Pattern[str], Callable[..., int]] = {
            re.compile(r"\$threshold_years_(\d+)"): self.get_threshold_years_date
        }

        # User defined variables. These receive only the captured regex groups.
        self.user_static_map: dict[re.Pattern[str], SubstitutionFunction] = {}

    def add_variable_substitution(
        self, pattern: str, substitution_function: SubstitutionFunction
    ):
        """Takes a valid regular expression PATTERN and a function
        who's arguments correspond with each regex group
        SUBSTITUTION_FUNCTION. Each captured regex group will be
        passed to the function as a str.

        Examples:
        vsm.add_variable_substitution(r\"\\$years since (\\d+) (\\d+)\", lambda x, y: int(x) + int(y))
        vsm.resolve(f"$years since {10} {12}", now) => 22
        """
        compiled = re.compile(pattern)
        # A user pattern replaces a built-in with the same pattern.
        self.dynamic_map.pop(compiled, None)
        self.user_static_map[compiled] = substitution_function

    def get_threshold_years_date(self, now: datetime, years: str) -> int:
        """
        Calculate the threshold date for a given number of years.

        Args:
            now (datetime): The current time.
            years (str): The number of years to subtract from the current year.

        Returns:
            int: The current date minux X years in YYYYMMDD format.
        """
        threshold_date = now.replace(year=now.year - int(years))
        return int(threshold_date.strftime("%Y%m%d"))

    def get_now(self, now: datetime) -> int:
        """
        Get the current timestamp.

        Returns:
            int: The current timestamp in seconds since the epoch.
        """
        return int(now.timestamp())

    def get_today_date(self, now: datetime) -> int:
        """
        Get today's date in YYYYMMDD format as a number.

        Returns:
            int: Today's date in YYYYMMDD format.
        """
        return int(now.strftime("%Y%m%d"))

    def get_tomorrow_date(self, now: datetime) -> int:
        """
        Get tomorrow's date in YYYYMMDD format as a number.

        Returns:
            int: Tomorrow's date in YYYYMMDD format.
        """
        return int((now + timedelta(days=1)).strftime("%Y%m%d"))

    def __contains__(self, key: str) -> bool:
        if key in self.static_map:
            return True
        patterns = [*self.dynamic_map, *self.user_static_map]
        return any(re.match(p, key) for p in patterns)

    def resolve(self, key: str, now: datetime) -> int | str:
        """Return the value of the variable KEY at time NOW."""
        if key in self.static_map:
            return self.static_map[key](now)
        for pattern, func in self.dynamic_map.items():
            if nmatch := re.match(pattern, key):
                return func(now, *nmatch.groups())
        for pattern, func in self.user_static_map.items():
            if nmatch := re.match(pattern, key):
                return func(*nmatch.groups())
        raise KeyError(f"Key {key} not found in format_args_function_map")


# Create an instance of the custom mapping class
variable_substitution_map = VariableSubstitutionMap()
