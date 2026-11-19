from datetime import UTC, datetime

import pytest
from api.verificationConfigs.user_variables import apply_user_variables
from api.verificationConfigs.variableSubstitutions import variable_substitution_map

NOW = datetime(2024, 3, 15, tzinfo=UTC)


@pytest.fixture(autouse=True)
def fresh_user_map(monkeypatch):
    monkeypatch.setattr(variable_substitution_map, "user_static_map", {})


def test_functions_can_use_the_files_own_imports(tmp_path):
    path = tmp_path / "vars.py"
    path.write_text(
        "import math\n"
        "def f(x):\n"
        "    return math.floor(float(x))\n"
        'variable_substitution_map.add_variable_substitution(r"\\$floor_(.+)", f)\n'
    )
    apply_user_variables(str(path))
    assert variable_substitution_map.resolve("$floor_2.7", NOW) == 2


def test_names_from_the_old_module_are_still_available(tmp_path):
    path = tmp_path / "vars.py"
    path.write_text(
        "def f(days):\n"
        "    return int((datetime(2024, 1, 1) + timedelta(days=int(days))).strftime('%Y%m%d'))\n"
        'variable_substitution_map.add_variable_substitution(r"\\$jan_plus_(\\d+)", f)\n'
    )
    apply_user_variables(str(path))
    assert variable_substitution_map.resolve("$jan_plus_2", NOW) == 20240103


def test_missing_file_is_ignored(tmp_path):
    apply_user_variables(str(tmp_path / "missing.py"))
    assert variable_substitution_map.user_static_map == {}
