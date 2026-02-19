import pytest
import unittest.mock
from unittest.mock import patch, MagicMock, AsyncMock
import requests
from api.core.webhook_utils import register_tenant_webhook
from api.main import on_tenant_startup
from api.core.webhook_utils import _register_via_tenant_api


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
        mock.REDIS_MODE = "none"  # Disabled by default
        mock.USE_REDIS_ADAPTER = False  # Computed from REDIS_MODE
        mock.ACAPY_TENANCY = "multi"
        mock.MT_ACAPY_WALLET_KEY = "wallet-key"
        mock.ACAPY_TENANT_WALLET_KEY = "wallet-key"
        mock.ACAPY_TENANT_WALLET_ID = "test-wallet-id"
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
async def test_webhook_registration_success_admin_api(mock_requests_put):
    """Test successful registration via standard Admin API."""
    mock_requests_put.return_value.status_code = 200

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller/webhooks",
        admin_url="http://acapy:8077",
        api_key="my-api-key",
        admin_api_key="admin-key",
        admin_api_key_name="x-api-key",
    )

    # Verify Admin API was called
    args, kwargs = mock_requests_put.call_args
    assert "multitenancy/wallet/test-wallet" in args[0]
    assert kwargs["headers"]["x-api-key"] == "admin-key"


@pytest.mark.asyncio
async def test_webhook_registration_fallback_success(mock_requests_put):
    """
    Test fallback to Tenant API when Admin API returns 403.
    This validates the new token_fetcher logic.
    """
    # 1. Admin API returns 403 (Forbidden)
    # 2. Tenant API returns 200 (Success)
    mock_requests_put.side_effect = [
        MagicMock(status_code=403, text="Forbidden"),
        MagicMock(status_code=200),
    ]

    # Create a mock token fetcher function
    mock_fetcher = MagicMock(return_value="injected-token")

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        token_fetcher=mock_fetcher,
    )

    # Verify flow
    assert mock_requests_put.call_count == 2

    # Check 1st call (Admin)
    admin_call = mock_requests_put.call_args_list[0]
    assert "multitenancy/wallet" in admin_call[0][0]

    # Check Token Fetcher was called
    mock_fetcher.assert_called_once()

    # Check 2nd call (Tenant)
    tenant_call = mock_requests_put.call_args_list[1]
    assert "tenant/wallet" in tenant_call[0][0]
    assert tenant_call[1]["headers"]["Authorization"] == "Bearer injected-token"


@pytest.mark.asyncio
async def test_webhook_registration_traction_mode_direct_tenant_api(mock_requests_put):
    """
    Test Traction mode (use_admin_api=False) which skips Admin API and goes direct to Tenant API.
    """
    mock_requests_put.return_value.status_code = 200
    mock_fetcher = MagicMock(return_value="traction-token")

    await register_tenant_webhook(
        wallet_id="ignored-in-traction-mode",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        token_fetcher=mock_fetcher,
        use_admin_api=False,  # Trigger direct tenant mode
    )

    # Verify flow
    assert mock_requests_put.call_count == 1

    # Verify call was to Tenant endpoint directly
    tenant_call = mock_requests_put.call_args_list[0]
    assert "tenant/wallet" in tenant_call[0][0]
    assert "multitenancy/wallet" not in tenant_call[0][0]
    assert tenant_call[1]["headers"]["Authorization"] == "Bearer traction-token"


@pytest.mark.asyncio
async def test_webhook_registration_no_fallback_without_fetcher(mock_requests_put):
    """Test 403 error does NOT trigger fallback if no token_fetcher provided."""
    mock_requests_put.return_value.status_code = 403

    # No fetcher provided
    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        token_fetcher=None,
    )

    # Should try Admin API once, fail, and stop (because no fetcher to try fallback)
    assert mock_requests_put.call_count == 1


@pytest.mark.asyncio
async def test_webhook_registration_missing_config(mock_requests_put):
    """Test early return if config is missing."""
    # Missing wallet_id AND use_admin_api=True (default)
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
        webhook_url="ftp://invalid-url",
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
async def test_startup_multi_tenant_injects_fetcher(mock_settings, mock_requests_put):
    """
    Critical Integration Test:
    Ensures main.py actually instantiates MultiTenantAcapy and passes the method.
    """
    mock_settings.ACAPY_TENANCY = "multi"
    mock_settings.ACAPY_TENANT_WALLET_KEY = "wallet-key"
    mock_settings.USE_REDIS_ADAPTER = False

    # Mock MultiTenantAcapy class to verify instantiation
    with patch("api.main.init_db", new_callable=AsyncMock), patch(
        "api.main.init_provider", new_callable=AsyncMock
    ), patch("api.main.get_db", new_callable=AsyncMock), patch(
        "api.main.MultiTenantAcapy"
    ) as mock_acapy_class, patch(
        "api.main.register_tenant_webhook", new_callable=AsyncMock
    ) as mock_register:

        # Setup mock instance
        mock_acapy_instance = MagicMock()
        mock_acapy_class.return_value = mock_acapy_instance
        # Mock the bound method we expect to be passed
        mock_acapy_instance.get_wallet_token = "bound-method-ref"

        await on_tenant_startup()

        # Verify register function was called
        assert mock_register.called

        # Verify the token_fetcher argument was passed correctly
        _, kwargs = mock_register.call_args
        assert kwargs["token_fetcher"] == "bound-method-ref"
        assert kwargs["use_admin_api"] == True


@pytest.mark.asyncio
async def test_startup_traction_mode_config(mock_settings, mock_requests_put):
    """
    Test startup logic in traction mode: uses TractionTenantAcapy and skips admin API.
    """
    mock_settings.ACAPY_TENANCY = "traction"
    mock_settings.USE_REDIS_ADAPTER = False

    with patch("api.main.init_db", new_callable=AsyncMock), patch(
        "api.main.init_provider", new_callable=AsyncMock
    ), patch("api.main.get_db", new_callable=AsyncMock), patch(
        "api.main.TractionTenantAcapy"
    ) as mock_traction_class, patch(
        "api.main.register_tenant_webhook", new_callable=AsyncMock
    ) as mock_register:

        mock_traction_instance = MagicMock()
        mock_traction_class.return_value = mock_traction_instance
        mock_traction_instance.get_wallet_token = "traction-token-fetcher"

        await on_tenant_startup()

        assert mock_register.called
        _, kwargs = mock_register.call_args
        assert kwargs["token_fetcher"] == "traction-token-fetcher"
        assert kwargs["use_admin_api"] == False


@pytest.mark.asyncio
async def test_startup_single_tenant_skips_registration(
    mock_settings, mock_requests_put
):
    """Test startup logic in single-tenant mode skips registration."""
    mock_settings.ACAPY_TENANCY = "single"
    mock_settings.USE_REDIS_ADAPTER = False

    with patch("api.main.init_db", new_callable=AsyncMock), patch(
        "api.main.init_provider", new_callable=AsyncMock
    ), patch("api.main.get_db", new_callable=AsyncMock), patch(
        "api.main.register_tenant_webhook", new_callable=AsyncMock
    ) as mock_register:

        await on_tenant_startup()

        assert not mock_register.called


@pytest.mark.asyncio
async def test_webhook_registration_401_stops_immediately(
    mock_requests_put, mock_sleep
):
    """Test that 401 errors (Unauthorized) stop retries immediately."""
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
async def test_startup_redis_check_success(mock_settings):
    """Test startup logic verifies Redis connection if adapter enabled."""
    mock_settings.REDIS_MODE = "single"  # Enable Redis via REDIS_MODE

    with patch("api.main.init_db", new_callable=AsyncMock), patch(
        "api.main.init_provider", new_callable=AsyncMock
    ), patch("api.main.get_db", new_callable=AsyncMock), patch(
        "api.main.can_we_reach_redis", return_value=True
    ) as mock_reach, patch(
        "api.main.build_redis_url", return_value="redis://localhost"
    ), patch(
        "api.main.normalize_redis_config"
    ), patch(
        "api.main.validate_redis_config"
    ):

        await on_tenant_startup()

        mock_reach.assert_called_once_with("redis://localhost")


@pytest.mark.asyncio
async def test_startup_redis_check_failure(mock_settings):
    """Test startup fails fast when Redis is configured but unreachable."""
    mock_settings.REDIS_MODE = "single"  # Enable Redis via REDIS_MODE
    mock_settings.REDIS_HOST = "redis:6379"

    with patch("api.main.init_db", new_callable=AsyncMock), patch(
        "api.main.init_provider", new_callable=AsyncMock
    ), patch("api.main.get_db", new_callable=AsyncMock), patch(
        "api.main.can_we_reach_redis", return_value=False
    ), patch(
        "api.main.build_redis_url", return_value="redis://localhost"
    ), patch(
        "api.main.normalize_redis_config"
    ), patch(
        "api.main.validate_redis_config"
    ):
        with pytest.raises(
            RuntimeError,
            match="REDIS_MODE=single is configured but Redis is not reachable",
        ):
            await on_tenant_startup()


@pytest.mark.asyncio
async def test_webhook_registration_missing_webhook_url(mock_requests_put):
    """Test early exit when webhook_url is missing."""
    await register_tenant_webhook(
        wallet_id="test",
        webhook_url="",  # Empty
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )
    mock_requests_put.assert_not_called()


@pytest.mark.asyncio
async def test_webhook_registration_traction_mode_missing_fetcher(mock_requests_put):
    """Test early exit in Traction mode if no token_fetcher is provided."""
    await register_tenant_webhook(
        wallet_id="ignored",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        token_fetcher=None,  # Missing
        use_admin_api=False,
    )
    mock_requests_put.assert_not_called()


@pytest.mark.asyncio
async def test_register_via_tenant_api_server_error(mock_requests_put):
    """Test _register_via_tenant_api handling 500 errors."""
    mock_requests_put.return_value.status_code = 500
    mock_requests_put.return_value.text = "Internal Error"

    fetcher = MagicMock(return_value="token")

    result = await _register_via_tenant_api("http://acapy", {}, fetcher)
    assert result is False


@pytest.mark.asyncio
async def test_register_via_tenant_api_client_error(mock_requests_put):
    """Test _register_via_tenant_api handling 400 errors."""
    mock_requests_put.return_value.status_code = 400
    mock_requests_put.return_value.text = "Bad Request"

    fetcher = MagicMock(return_value="token")

    result = await _register_via_tenant_api("http://acapy", {}, fetcher)
    assert result is False


@pytest.mark.asyncio
async def test_register_via_tenant_api_exception(mock_requests_put):
    """Test _register_via_tenant_api handling exceptions."""
    mock_requests_put.side_effect = Exception("Network Down")

    fetcher = MagicMock(return_value="token")

    result = await _register_via_tenant_api("http://acapy", {}, fetcher)
    assert result is False


@pytest.mark.asyncio
async def test_webhook_registration_unexpected_status_code(mock_requests_put):
    """Test handling of unexpected status codes (e.g. 418)."""
    mock_requests_put.return_value.status_code = 418

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        use_admin_api=True,
    )
    # Should log warning and exit loop (not retry)
    assert mock_requests_put.call_count == 1


@pytest.mark.asyncio
async def test_webhook_registration_masks_api_key_in_logs(mock_requests_put):
    """Test that the API key fragment in webhook URL is masked in logs."""
    mock_requests_put.return_value.status_code = 200

    # Use a fresh mock for the logger to inspect calls specifically for this test
    with patch("api.core.webhook_utils.logger") as mock_logger:
        secret_key = "super-secret-key"
        base_url = "http://controller/webhooks"

        await register_tenant_webhook(
            wallet_id="test-wallet",
            webhook_url=base_url,
            admin_url="http://acapy",
            api_key=secret_key,  # This gets appended as #secret-key
            admin_api_key=None,
            admin_api_key_name=None,
        )

        # Get all arguments passed to info calls
        info_calls = [args[0] for args, _ in mock_logger.info.call_args_list]

        # Assert masking happened
        expected_log_fragment = f"{base_url}#*****"
        assert any(
            expected_log_fragment in call for call in info_calls
        ), f"Expected masked URL '{expected_log_fragment}' not found in logs: {info_calls}"

        # Assert secret is NOT present
        assert not any(
            secret_key in call for call in info_calls
        ), "SECRET KEY LEAKED IN LOGS!"
