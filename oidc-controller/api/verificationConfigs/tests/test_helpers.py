from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from api.verificationConfigs.helpers import (
    VariableSubstitutionError,
    replace_proof_variables,
)
from api.verificationConfigs.variableSubstitutions import VariableSubstitutionMap

NOW = datetime(2024, 1, 1, tzinfo=UTC)

mock_variable_substitution_map = VariableSubstitutionMap()
mock_variable_substitution_map.add_variable_substitution(r"\$var1", lambda: "value1")
mock_variable_substitution_map.add_variable_substitution(r"\$var2", lambda: "value2")


@patch(
    "api.verificationConfigs.helpers.variable_substitution_map",
    mock_variable_substitution_map,
)
def test_replace_proof_variables_empty_dict():
    assert replace_proof_variables({}, NOW) == {}


@patch(
    "api.verificationConfigs.helpers.variable_substitution_map",
    mock_variable_substitution_map,
)
def test_replace_proof_variables_no_variables():
    input_dict = {"key1": "value1", "key2": "value2"}
    assert replace_proof_variables(input_dict, NOW) == input_dict


@patch(
    "api.verificationConfigs.helpers.variable_substitution_map",
    mock_variable_substitution_map,
)
def test_replace_proof_variables_with_variables():
    input_dict = {"key1": "$var1", "key2": "$var2"}
    expected_dict = {"key1": "value1", "key2": "value2"}
    assert replace_proof_variables(input_dict, NOW) == expected_dict


@patch(
    "api.verificationConfigs.helpers.variable_substitution_map",
    mock_variable_substitution_map,
)
def test_replace_proof_variables_variable_not_found():
    input_dict = {"key1": "$var3"}
    with pytest.raises(VariableSubstitutionError):
        replace_proof_variables(input_dict, NOW)


@patch(
    "api.verificationConfigs.helpers.variable_substitution_map",
    mock_variable_substitution_map,
)
def test_replace_proof_variables_nested_dict():
    input_dict = {"key1": {"key2": "$var1"}}
    expected_dict = {"key1": {"key2": "value1"}}
    assert replace_proof_variables(input_dict, NOW) == expected_dict


@patch(
    "api.verificationConfigs.helpers.variable_substitution_map",
    mock_variable_substitution_map,
)
def test_replace_proof_variables_list():
    input_dict = {"key1": [{"key2": "$var2"}]}
    expected_dict = {"key1": [{"key2": "value2"}]}
    assert replace_proof_variables(input_dict, NOW) == expected_dict
