import pytest
from api.core.config import strtobool


def test_strtobool():
    # Test valid truthy values
    truthy_values = ["y", "yes", "t", "true", "on", "1", True]
    for value in truthy_values:
        assert strtobool(value) is True

    # Test valid falsy values
    falsy_values = ["n", "no", "f", "false", "off", "0", False]
    for value in falsy_values:
        assert strtobool(value) is False

    # Test invalid input
    with pytest.raises(ValueError, match="invalid truth value invalid"):
        strtobool("invalid")
