import pytest
import logging
import os
import importlib
from unittest.mock import patch
from api.core.config import (
    strtobool,
    determin_log_level,
    FactoryConfig,
    EnvironmentEnum,
)
from pydantic import ValidationError 


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


class TestDeterminLogLevel:
    """Test determin_log_level function."""

    @patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"})
    def test_log_level_debug(self):
        """Test DEBUG log level."""
        assert determin_log_level() == logging.DEBUG

    @patch.dict(os.environ, {"LOG_LEVEL": "INFO"})
    def test_log_level_info(self):
        """Test INFO log level."""
        assert determin_log_level() == logging.INFO

    @patch.dict(os.environ, {"LOG_LEVEL": "WARNING"})
    def test_log_level_warning(self):
        """Test WARNING log level."""
        assert determin_log_level() == logging.WARNING

    @patch.dict(os.environ, {"LOG_LEVEL": "ERROR"})
    def test_log_level_error(self):
        """Test ERROR log level."""
        assert determin_log_level() == logging.ERROR

    @patch.dict(os.environ, {"LOG_LEVEL": "INVALID"})
    def test_log_level_default(self):
        """Test default log level for invalid value."""
        assert determin_log_level() == logging.DEBUG

    @patch.dict(os.environ, {}, clear=True)
    def test_log_level_missing(self):
        """Test default log level when LOG_LEVEL is not set."""
        if "LOG_LEVEL" in os.environ:
            del os.environ["LOG_LEVEL"]
        assert determin_log_level() == logging.DEBUG


class TestFactoryConfig:
    """Test FactoryConfig factory."""

    def test_factory_config_local(self):
        """Test FactoryConfig returns LocalConfig for local environment."""
        from api.core.config import LocalConfig

        config_factory = FactoryConfig(EnvironmentEnum.LOCAL.value)
        result = config_factory()
        assert isinstance(result, LocalConfig)

    def test_factory_config_prod(self):
        """Test FactoryConfig returns ProdConfig for production environment."""
        from api.core.config import ProdConfig

        config_factory = FactoryConfig("production")
        result = config_factory()
        assert isinstance(result, ProdConfig)

    def test_factory_config_none(self):
        """Test FactoryConfig returns ProdConfig for None environment."""
        from api.core.config import ProdConfig

        config_factory = FactoryConfig(None)
        result = config_factory()
        assert isinstance(result, ProdConfig)


class TestConfigValidation:
    """Test configuration validation logic."""

    def test_invalid_proof_format_raises_error(self):
        """Test that initializing settings with invalid ACAPY_PROOF_FORMAT raises ValueError."""
        with patch.dict(os.environ, {"ACAPY_PROOF_FORMAT": "invalid_format"}):
            with pytest.raises(
                ValueError, match="ACAPY_PROOF_FORMAT must be 'indy' or 'anoncreds'"
            ):
                from api.core import config

                importlib.reload(config)


class TestOIDCConfig:
    """Tests for OIDC-specific configuration."""

    def test_default_token_ttl(self):
        """Test default TTL is 3600 seconds."""
        # Use patch to ensure clean environment
        with patch.dict(os.environ, {}, clear=True):
            # We need to reload the config module or recreate the config object
            # Since FactoryConfig creates new instances, we can use that
            config = FactoryConfig(EnvironmentEnum.LOCAL.value)()
            assert config.OIDC_ACCESS_TOKEN_TTL == 3600

    def test_custom_token_ttl(self):
        """Test overriding TTL via environment variable."""
        with patch.dict(os.environ, {"OIDC_ACCESS_TOKEN_TTL": "7200"}):
            config = FactoryConfig(EnvironmentEnum.LOCAL.value)()
            assert config.OIDC_ACCESS_TOKEN_TTL == 7200

    def test_invalid_token_ttl_raises_error(self):
        """Test that negative or zero TTL raises ValidationError."""
        with patch.dict(os.environ, {"OIDC_ACCESS_TOKEN_TTL": "0"}):
            with pytest.raises(ValidationError) as exc:
                FactoryConfig(EnvironmentEnum.LOCAL.value)()
            assert "OIDC_ACCESS_TOKEN_TTL must be a positive integer" in str(exc.value)

        with patch.dict(os.environ, {"OIDC_ACCESS_TOKEN_TTL": "-100"}):
            with pytest.raises(ValidationError) as exc:
                FactoryConfig(EnvironmentEnum.LOCAL.value)()
            assert "OIDC_ACCESS_TOKEN_TTL must be a positive integer" in str(exc.value)