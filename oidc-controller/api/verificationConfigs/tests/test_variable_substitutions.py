from datetime import UTC, datetime

import pytest
from api.verificationConfigs.variableSubstitutions import VariableSubstitutionMap

NOW = datetime(2024, 3, 15, 12, 30, tzinfo=UTC)


def test_now():
    vsm = VariableSubstitutionMap()
    assert vsm.resolve("$now", NOW) == int(NOW.timestamp())


def test_today_int():
    vsm = VariableSubstitutionMap()
    assert vsm.resolve("$today_int", NOW) == 20240315


def test_tomorrow_int():
    vsm = VariableSubstitutionMap()
    assert vsm.resolve("$tomorrow_int", NOW) == 20240316


def test_threshold_years():
    vsm = VariableSubstitutionMap()
    assert vsm.resolve("$threshold_years_5", NOW) == 20190315


def test_user_defined_func():
    vsm = VariableSubstitutionMap()

    def func(x: int, y) -> int:
        return int(x) + int(y)

    vsm.add_variable_substitution(r"\$years since (\d+) (\d+)", func)
    days = 10
    years = 22
    assert f"$years since {years} {days}" in vsm
    assert vsm.resolve(f"$years since {years} {days}", NOW) == years + days


def test_user_pattern_replaces_builtin():
    vsm = VariableSubstitutionMap()
    vsm.add_variable_substitution(r"\$threshold_years_(\d+)", lambda years: -1)
    assert vsm.resolve("$threshold_years_5", NOW) == -1


def test_contains_static_variable():
    vsm = VariableSubstitutionMap()
    assert "$now" in vsm
    assert "$today_int" in vsm
    assert "$tomorrow_int" in vsm


def test_contains_dynamic_variable():
    vsm = VariableSubstitutionMap()
    assert "$threshold_years_5" in vsm


def test_resolve_key_error():
    vsm = VariableSubstitutionMap()
    assert "$non_existent_key" not in vsm
    with pytest.raises(KeyError):
        vsm.resolve("$non_existent_key", NOW)
