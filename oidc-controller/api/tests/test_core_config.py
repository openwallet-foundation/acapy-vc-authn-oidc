import importlib
import logging
import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from api.config import (
    EnvironmentEnum,
    FactoryConfig,
    determin_log_level,
    strtobool,
    validate_redis_config,
)


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
        from api.config import LocalConfig

        config_factory = FactoryConfig(EnvironmentEnum.LOCAL.value)
        result = config_factory()
        assert isinstance(result, LocalConfig)

    def test_factory_config_prod(self):
        """Test FactoryConfig returns ProdConfig for production environment."""
        from api.config import ProdConfig

        config_factory = FactoryConfig("production")
        result = config_factory()
        assert isinstance(result, ProdConfig)

    def test_factory_config_none(self):
        """Test FactoryConfig returns ProdConfig for None environment."""
        from api.config import ProdConfig

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
                from api import config

                importlib.reload(config)


class TestSettingsNormalization:
    """Settings are validated once when built, since they are frozen."""

    def test_controller_url_is_required(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValidationError, match="CONTROLLER_URL"):
                FactoryConfig(EnvironmentEnum.LOCAL.value)()

    def test_redis_mode_and_empty_password_are_normalized(self):
        with patch.dict(os.environ, {"REDIS_MODE": " Single ", "REDIS_PASSWORD": ""}):
            config = FactoryConfig(EnvironmentEnum.LOCAL.value)()
        assert config.REDIS_MODE == "single"
        assert config.REDIS_PASSWORD is None


class TestOIDCConfig:
    """Tests for OIDC-specific configuration."""

    def test_default_token_ttl(self):
        """Test default TTL is 3600 seconds."""
        # Use patch to ensure clean environment
        with patch.dict(
            os.environ, {"CONTROLLER_URL": "https://controller"}, clear=True
        ):
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


class TestValidateRedisConfig:
    """Test validate_redis_config function for configuration validation."""

    @patch("api.config.settings")
    def test_validate_redis_config_mode_none(self, mock_settings):
        """Test validation passes for mode=none."""
        mock_settings.REDIS_MODE = "none"

        # Should not raise
        validate_redis_config()

    @patch("api.config.settings")
    def test_validate_redis_config_single_mode_valid(self, mock_settings):
        """Test validation passes for valid single mode config with host:port."""
        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis-host:6379"

        # Should not raise
        validate_redis_config()

    @patch("api.config.settings")
    def test_validate_redis_config_single_mode_bare_hostname_invalid(
        self, mock_settings
    ):
        """Test that validate_redis_config rejects a bare hostname (no port)."""
        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis-host"  # no port — invalid format

        with pytest.raises(ValueError) as exc:
            validate_redis_config()
        assert "Invalid node:" in str(exc.value)

    @patch("api.config.settings")
    def test_validate_redis_config_single_mode_with_multiple_hosts_fails(
        self, mock_settings
    ):
        """Test validation fails for single mode with multiple hosts."""
        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis1:6379,redis2:6379"

        with pytest.raises(ValueError) as exc:
            validate_redis_config()
        assert "REDIS_MODE=single but REDIS_HOST contains multiple hosts" in str(
            exc.value
        )

    @patch("api.config.settings")
    def test_validate_redis_config_sentinel_mode_valid(self, mock_settings):
        """Test validation passes for valid sentinel mode config."""
        mock_settings.REDIS_MODE = "sentinel"
        mock_settings.REDIS_HOST = "sentinel1:26379,sentinel2:26379,sentinel3:26379"

        # Should not raise
        validate_redis_config()

    @patch("api.config.settings")
    def test_validate_redis_config_sentinel_mode_invalid_format(self, mock_settings):
        """Test validation fails for sentinel mode with invalid host format."""
        mock_settings.REDIS_MODE = "sentinel"
        mock_settings.REDIS_HOST = "sentinel1,sentinel2"  # Missing ports

        with pytest.raises(ValueError) as exc:
            validate_redis_config()
        assert "requires REDIS_HOST as host:port pairs" in str(exc.value)

    @patch("api.config.settings")
    def test_validate_redis_config_cluster_mode_valid(self, mock_settings):
        """Test validation passes for valid cluster mode config."""
        mock_settings.REDIS_MODE = "cluster"
        mock_settings.REDIS_HOST = "node1:6379,node2:6379,node3:6379"

        # Should not raise
        validate_redis_config()

    @patch("api.config.settings")
    def test_validate_redis_config_cluster_mode_invalid_format(self, mock_settings):
        """Test validation fails for cluster mode with invalid host format."""
        mock_settings.REDIS_MODE = "cluster"
        mock_settings.REDIS_HOST = "node1:abc,node2:6379"  # Non-numeric port

        with pytest.raises(ValueError) as exc:
            validate_redis_config()
        assert "Invalid node:" in str(exc.value)

    def test_invalid_redis_mode_fails_when_settings_load(self):
        """An unknown REDIS_MODE is rejected when settings are built."""
        with patch.dict(os.environ, {"REDIS_MODE": "invalid_mode"}):
            with pytest.raises(ValidationError, match="REDIS_MODE"):
                FactoryConfig(EnvironmentEnum.LOCAL.value)()

    @patch("api.config.settings")
    def test_validate_redis_config_sentinel_with_ip_addresses(self, mock_settings):
        """Test validation passes for sentinel mode with IP addresses."""
        mock_settings.REDIS_MODE = "sentinel"
        mock_settings.REDIS_HOST = "192.168.1.10:26379,192.168.1.11:26379"

        # Should not raise
        validate_redis_config()

    @patch("api.config.settings")
    def test_validate_redis_config_cluster_single_node(self, mock_settings):
        """Test validation passes for cluster mode with single node."""
        mock_settings.REDIS_MODE = "cluster"
        mock_settings.REDIS_HOST = "cluster-node:6379"

        # Should not raise
        validate_redis_config()
