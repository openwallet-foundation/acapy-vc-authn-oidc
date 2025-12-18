import pytest
import os
import importlib
from unittest.mock import patch, MagicMock
from api.core import config


class TestConfigEdgeCases:
    """
    Tests specifically designed to hit edge cases in config.py
    that run at module level (import time).
    """

    def reload_config(self):
        """Helper to reload the config module to re-run top-level code."""
        importlib.reload(config)

    def test_proof_format_validation_failure(self):
        """
        Test that ValueError is raised when ACAPY_PROOF_FORMAT is invalid.
        Covers: config.py lines 308-311 (validation logic)
        """
        with patch.dict(os.environ, {"ACAPY_PROOF_FORMAT": "invalid_format"}):
            with pytest.raises(ValueError) as exc:
                self.reload_config()
            assert "ACAPY_PROOF_FORMAT must be 'indy' or 'anoncreds'" in str(exc.value)

    def test_webhook_warning_multi_tenant_missing_url(self):
        """
        Test that warning is logged when multi-tenant mode is on but webhook URL is missing.
        Covers: config.py lines 314-319 (warning logic)
        """
        env_vars = {
            "ACAPY_TENANCY": "multi",
            "CONTROLLER_WEB_HOOK_URL": "",
            "ACAPY_PROOF_FORMAT": "indy",
        }

        # Patch structlog.getLogger to return a mock so we can capture calls during reload
        mock_logger = MagicMock()
        with patch("structlog.getLogger", return_value=mock_logger):
            with patch.dict(os.environ, env_vars):
                self.reload_config()

                # Verify warning called. Note: reload might log other warnings too (e.g. ACAPY_AGENT_URL missing)
                # so we check if our specific message was among the calls.
                assert mock_logger.warning.called

                # Check args of all warning calls
                found = False
                for call in mock_logger.warning.call_args_list:
                    if (
                        "ACAPY_TENANCY is set to 'multi' but CONTROLLER_WEB_HOOK_URL is missing"
                        in call[0][0]
                    ):
                        found = True
                        break
                assert found, "Expected warning message not found in logger calls"

    def test_webhook_warning_not_triggered_when_valid(self):
        """
        Test that warning is NOT logged when configuration is correct.
        Covers: The 'else' or fall-through path of the warning check.
        """
        env_vars = {
            "ACAPY_TENANCY": "multi",
            "CONTROLLER_WEB_HOOK_URL": "http://valid-url",
            "ACAPY_PROOF_FORMAT": "indy",
        }

        mock_logger = MagicMock()
        with patch("structlog.getLogger", return_value=mock_logger):
            with patch.dict(os.environ, env_vars):
                self.reload_config()

                # Check that SPECIFIC warning was NOT called
                for call in mock_logger.warning.call_args_list:
                    assert "ACAPY_TENANCY is set to 'multi'" not in call[0][0]

    def test_webhook_warning_not_triggered_single_tenant(self):
        """
        Test that warning is NOT logged in single tenant mode.
        """
        env_vars = {
            "ACAPY_TENANCY": "single",
            "CONTROLLER_WEB_HOOK_URL": "",
            "ACAPY_PROOF_FORMAT": "indy",
        }

        mock_logger = MagicMock()
        with patch("structlog.getLogger", return_value=mock_logger):
            with patch.dict(os.environ, env_vars):
                self.reload_config()

                for call in mock_logger.warning.call_args_list:
                    assert "ACAPY_TENANCY is set to 'multi'" not in call[0][0]

    def test_token_ttl_validation_failure(self):
        """
        Test that ValueError is raised when ACAPY_TOKEN_CACHE_TTL is invalid (<= 0).
        """
        with patch.dict(os.environ, {"ACAPY_TOKEN_CACHE_TTL": "0"}):
            with pytest.raises(ValueError) as exc:
                self.reload_config()
            assert "ACAPY_TOKEN_CACHE_TTL must be a positive integer" in str(exc.value)

        with patch.dict(os.environ, {"ACAPY_TOKEN_CACHE_TTL": "-10"}):
            with pytest.raises(ValueError) as exc:
                self.reload_config()
            assert "ACAPY_TOKEN_CACHE_TTL must be a positive integer" in str(exc.value)
