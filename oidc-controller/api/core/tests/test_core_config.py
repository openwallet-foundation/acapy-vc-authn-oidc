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
    _get_redis_mode,
    normalize_redis_config,
    validate_redis_config,
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


class TestGetRedisMode:
    """Test _get_redis_mode function for Redis mode determination."""

    @patch.dict(os.environ, {"REDIS_MODE": "single"}, clear=False)
    def test_redis_mode_from_env(self):
        """Test REDIS_MODE is read directly from environment."""
        result = _get_redis_mode()
        assert result == "single"

    @patch.dict(os.environ, {"REDIS_MODE": "SENTINEL"}, clear=False)
    def test_redis_mode_case_insensitive(self):
        """Test REDIS_MODE is converted to lowercase."""
        result = _get_redis_mode()
        assert result == "sentinel"

    @patch.dict(os.environ, {"REDIS_MODE": "cluster"}, clear=False)
    def test_redis_mode_cluster(self):
        """Test REDIS_MODE cluster mode."""
        result = _get_redis_mode()
        assert result == "cluster"

    @patch.dict(os.environ, {"USE_REDIS_ADAPTER": "true"}, clear=False)
    def test_legacy_use_redis_adapter_true(self):
        """Test legacy USE_REDIS_ADAPTER=true maps to single mode."""
        # Remove REDIS_MODE if present
        env = os.environ.copy()
        env.pop("REDIS_MODE", None)
        with patch.dict(os.environ, env, clear=True):
            os.environ["USE_REDIS_ADAPTER"] = "true"
            result = _get_redis_mode()
            assert result == "single"

    @patch.dict(os.environ, {}, clear=True)
    def test_default_mode_none(self):
        """Test default mode is none when no env vars set."""
        result = _get_redis_mode()
        assert result == "none"


class TestValidateRedisConfig:
    """Test validate_redis_config function for configuration validation."""

    @patch("api.core.config.settings")
    def test_validate_redis_config_mode_none(self, mock_settings):
        """Test validation passes for mode=none."""
        mock_settings.REDIS_MODE = "none"

        # Should not raise
        validate_redis_config()

    @patch("api.core.config.settings")
    def test_validate_redis_config_single_mode_valid(self, mock_settings):
        """Test validation passes for valid single mode config with host:port."""
        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis-host:6379"

        # Should not raise
        validate_redis_config()

    @patch("api.core.config.settings")
    def test_validate_redis_config_single_mode_bare_hostname_invalid(
        self, mock_settings
    ):
        """Test that validate_redis_config rejects a bare hostname (no port).

        normalize_redis_config() must be called first to expand bare hostnames.
        validate_redis_config() is pure and does not perform that transformation.
        """
        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis-host"  # no port — not yet normalized

        with pytest.raises(ValueError) as exc:
            validate_redis_config()
        assert "Invalid node:" in str(exc.value)

    @patch("api.core.config.settings")
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

    @patch("api.core.config.settings")
    def test_validate_redis_config_sentinel_mode_valid(self, mock_settings):
        """Test validation passes for valid sentinel mode config."""
        mock_settings.REDIS_MODE = "sentinel"
        mock_settings.REDIS_HOST = "sentinel1:26379,sentinel2:26379,sentinel3:26379"

        # Should not raise
        validate_redis_config()

    @patch("api.core.config.settings")
    def test_validate_redis_config_sentinel_mode_invalid_format(self, mock_settings):
        """Test validation fails for sentinel mode with invalid host format."""
        mock_settings.REDIS_MODE = "sentinel"
        mock_settings.REDIS_HOST = "sentinel1,sentinel2"  # Missing ports

        with pytest.raises(ValueError) as exc:
            validate_redis_config()
        assert "requires REDIS_HOST as host:port pairs" in str(exc.value)

    @patch("api.core.config.settings")
    def test_validate_redis_config_cluster_mode_valid(self, mock_settings):
        """Test validation passes for valid cluster mode config."""
        mock_settings.REDIS_MODE = "cluster"
        mock_settings.REDIS_HOST = "node1:6379,node2:6379,node3:6379"

        # Should not raise
        validate_redis_config()

    @patch("api.core.config.settings")
    def test_validate_redis_config_cluster_mode_invalid_format(self, mock_settings):
        """Test validation fails for cluster mode with invalid host format."""
        mock_settings.REDIS_MODE = "cluster"
        mock_settings.REDIS_HOST = "node1:abc,node2:6379"  # Non-numeric port

        with pytest.raises(ValueError) as exc:
            validate_redis_config()
        assert "Invalid node:" in str(exc.value)

    @patch("api.core.config.settings")
    def test_validate_redis_config_invalid_mode(self, mock_settings):
        """Test validation fails for invalid Redis mode."""
        mock_settings.REDIS_MODE = "invalid_mode"

        with pytest.raises(ValueError) as exc:
            validate_redis_config()
        assert "Invalid REDIS_MODE: 'invalid_mode'" in str(exc.value)
        assert "Must be one of: none, single, sentinel, cluster" in str(exc.value)

    @patch("api.core.config.settings")
    def test_validate_redis_config_sentinel_with_ip_addresses(self, mock_settings):
        """Test validation passes for sentinel mode with IP addresses."""
        mock_settings.REDIS_MODE = "sentinel"
        mock_settings.REDIS_HOST = "192.168.1.10:26379,192.168.1.11:26379"

        # Should not raise
        validate_redis_config()

    @patch("api.core.config.settings")
    def test_validate_redis_config_cluster_single_node(self, mock_settings):
        """Test validation passes for cluster mode with single node."""
        mock_settings.REDIS_MODE = "cluster"
        mock_settings.REDIS_HOST = "cluster-node:6379"

        # Should not raise
        validate_redis_config()


class TestNormalizeRedisConfig:
    """Test normalize_redis_config — backwards-compat mutation of settings."""

    @patch("api.core.config.settings")
    def test_normalize_bare_hostname_appends_port(self, mock_settings):
        """Test that a bare hostname gets REDIS_PORT appended."""
        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis-host"
        mock_settings.REDIS_PORT = 6379

        normalize_redis_config()

        assert mock_settings.REDIS_HOST == "redis-host:6379"

    @patch("api.core.config.settings")
    def test_normalize_host_with_port_unchanged(self, mock_settings):
        """Test that a host already in host:port format is not modified."""
        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis-host:6379"

        normalize_redis_config()

        assert mock_settings.REDIS_HOST == "redis-host:6379"

    @patch("api.core.config.settings")
    def test_normalize_non_single_mode_unchanged(self, mock_settings):
        """Test that non-single modes are not touched."""
        mock_settings.REDIS_MODE = "sentinel"
        mock_settings.REDIS_HOST = "sentinel1"  # bare, but not single mode

        normalize_redis_config()

        assert mock_settings.REDIS_HOST == "sentinel1"

    @patch("api.core.config.settings")
    def test_normalize_none_mode_unchanged(self, mock_settings):
        """Test that mode=none is a no-op."""
        mock_settings.REDIS_MODE = "none"
        mock_settings.REDIS_HOST = "redis"

        normalize_redis_config()

        assert mock_settings.REDIS_HOST == "redis"
