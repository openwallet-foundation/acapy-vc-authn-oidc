import pytest
import asyncio
import unittest.mock
from unittest.mock import patch, MagicMock, AsyncMock
import requests
from api.core.webhook_utils import register_tenant_webhook
from api.main import on_tenant_startup
from api.core.config import settings


@pytest.fixture
def mock_settings():
    """Mock settings for webhook registration tests."""
    with patch("api.main.settings") as mock:
        mock.CONTROLLER_WEB_HOOK_URL = "http://controller:5000/webhooks"
        mock.MT_ACAPY_WALLET_ID = "test-wallet-id"
        mock.CONTROLLER_API_KEY = "controller-api-key"
        mock.ACAPY_ADMIN_URL = "http://acapy:8077"
        mock.ST_ACAPY_ADMIN_API_KEY_NAME = "x-api-key"
        mock.ST_ACAPY_ADMIN_API_KEY = "admin-api-key"
        # Default safe values
        mock.USE_REDIS_ADAPTER = False
        mock.ACAPY_TENANCY = "multi"
        yield mock


@pytest.fixture
def mock_requests_put():
    """Mock requests.put."""
    with patch("api.core.webhook_utils.requests.put") as mock:
        yield mock


@pytest.fixture
def mock_sleep():
    """Mock asyncio.sleep to prevent slow tests."""
    with patch("api.core.webhook_utils.asyncio.sleep", new_callable=AsyncMock) as mock:
        yield mock


@pytest.mark.asyncio
async def test_webhook_registration_success(mock_requests_put):
    """Test successful webhook registration with API key injection."""
    mock_requests_put.return_value.status_code = 200

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller/webhooks",
        admin_url="http://acapy:8077",
        api_key="my-api-key",
        admin_api_key="admin-key",
        admin_api_key_name="x-api-key",
    )

    # Verify URL construction (Hash Hack)
    expected_url = "http://controller/webhooks#my-api-key"

    # Verify arguments passed to requests.put
    args, kwargs = mock_requests_put.call_args
    assert args[0] == "http://acapy:8077/multitenancy/wallet/test-wallet"
    assert kwargs["json"] == {"wallet_webhook_urls": [expected_url]}
    assert kwargs["headers"] == {"x-api-key": "admin-key"}


@pytest.mark.asyncio
async def test_webhook_registration_missing_config(mock_requests_put):
    """Test early return if config is missing."""
    # Missing wallet_id
    await register_tenant_webhook(
        wallet_id=None,
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )

    mock_requests_put.assert_not_called()


@pytest.mark.asyncio
async def test_webhook_registration_invalid_url(mock_requests_put):
    """Test validation for invalid URL protocol."""
    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="ftp://invalid-url",  # Invalid protocol
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )

    mock_requests_put.assert_not_called()


@pytest.mark.asyncio
async def test_webhook_registration_retry_logic_with_backoff(
    mock_requests_put, mock_sleep
):
    """
    Test that the function retries on connection error with exponential backoff.
    """
    # Fail twice with ConnectionError, then succeed
    mock_requests_put.side_effect = [
        requests.exceptions.ConnectionError("Not ready"),
        requests.exceptions.ConnectionError("Still not ready"),
        MagicMock(status_code=200),
    ]

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )

    # Verify call count
    assert mock_requests_put.call_count == 3

    # Verify backoff delays: 2s, then 4s
    # sleep is called 'attempt' times (2 times for 3 attempts, as success happens on 3rd)
    assert mock_sleep.call_count == 2

    # Check arguments passed to sleep
    # First retry (attempt 0 failure): 2 * (2^0) = 2
    # Second retry (attempt 1 failure): 2 * (2^1) = 4
    mock_sleep.assert_has_calls([unittest.mock.call(2), unittest.mock.call(4)])


@pytest.mark.asyncio
async def test_webhook_registration_fatal_auth_error(mock_requests_put, mock_sleep):
    """Test that 401/403 errors stop retries immediately."""
    mock_requests_put.return_value.status_code = 401  # Unauthorized

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )

    assert mock_requests_put.call_count == 1  # Should not retry
    mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_webhook_registration_exhaust_retries(mock_requests_put, mock_sleep):
    """Test that function handles exhausting all retries gracefully."""
    mock_requests_put.side_effect = requests.exceptions.ConnectionError("Down")

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )

    # Implementation defined max_retries = 5
    assert mock_requests_put.call_count == 5


@pytest.mark.asyncio
async def test_webhook_registration_unexpected_exception(mock_requests_put, mock_sleep):
    """Test that generic exceptions stop execution immediately (no retry)."""
    mock_requests_put.side_effect = Exception("Something weird happened")

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )

    assert mock_requests_put.call_count == 1
    mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_startup_multi_tenant_registers_webhook(mock_settings, mock_requests_put):
    """Test startup logic in multi-tenant mode calls registration."""
    mock_settings.ACAPY_TENANCY = "multi"
    mock_settings.USE_REDIS_ADAPTER = False

    with patch("api.main.init_db", new_callable=AsyncMock), patch(
        "api.main.init_provider", new_callable=AsyncMock
    ), patch("api.main.get_db", new_callable=AsyncMock), patch(
        "api.main.register_tenant_webhook", new_callable=AsyncMock
    ) as mock_register:

        await on_tenant_startup()

        assert mock_register.called


@pytest.mark.asyncio
async def test_startup_single_tenant_skips_registration(
    mock_settings, mock_requests_put
):
    """Test startup logic in single-tenant mode skips registration."""
    mock_settings.ACAPY_TENANCY = "single"
    mock_settings.USE_REDIS_ADAPTER = False

    with patch("api.main.init_db", new_callable=AsyncMock), patch(
        "api.main.init_provider", new_callable=AsyncMock
    ), patch("api.main.get_db", new_callable=AsyncMock):

        await on_tenant_startup()

        assert not mock_requests_put.called


@pytest.mark.asyncio
async def test_startup_redis_check_success(mock_settings):
    """Test startup logic verifies Redis connection if adapter enabled."""
    mock_settings.USE_REDIS_ADAPTER = True

    # Mock redis client
    mock_redis_client = AsyncMock()
    mock_redis_client.ping.return_value = True

    with patch("api.main.init_db", new_callable=AsyncMock), patch(
        "api.main.init_provider", new_callable=AsyncMock
    ), patch("api.main.get_db", new_callable=AsyncMock), patch(
        "api.main.async_redis.from_url", return_value=mock_redis_client
    ), patch(
        "api.main._build_redis_url", return_value="redis://localhost"
    ):

        await on_tenant_startup()

        mock_redis_client.ping.assert_called_once()
        mock_redis_client.close.assert_called_once()


@pytest.mark.asyncio
async def test_startup_redis_check_failure(mock_settings):
    """Test startup logic handles Redis connection failure gracefully."""
    mock_settings.USE_REDIS_ADAPTER = True

    with patch("api.main.init_db", new_callable=AsyncMock), patch(
        "api.main.init_provider", new_callable=AsyncMock
    ), patch("api.main.get_db", new_callable=AsyncMock), patch(
        "api.main.async_redis.from_url", side_effect=Exception("Redis Down")
    ), patch(
        "api.main._build_redis_url", return_value="redis://localhost"
    ), patch(
        "api.main._handle_redis_failure"
    ) as mock_handler:

        await on_tenant_startup()

        # Should log error but continue startup
        mock_handler.assert_called_once()
