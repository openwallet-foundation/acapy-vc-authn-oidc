import pytest
import unittest.mock
from unittest.mock import patch, MagicMock, AsyncMock
import httpx
import respx
from api.core.webhook_utils import register_tenant_webhook, _register_via_tenant_api
from api.main import on_tenant_startup


@pytest.fixture
def http_client():
    return httpx.AsyncClient()


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
        mock.ACAPY_TENANCY = "multi"
        mock.MT_ACAPY_WALLET_KEY = "wallet-key"
        mock.ACAPY_TENANT_WALLET_KEY = "wallet-key"
        mock.ACAPY_TENANT_WALLET_ID = "test-wallet-id"
        yield mock


@pytest.fixture
def mock_sleep():
    """Mock asyncio.sleep to prevent slow tests."""
    with patch("api.core.webhook_utils.asyncio.sleep", new_callable=AsyncMock) as mock:
        yield mock


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_success_admin_api(http_client):
    route = respx.put("http://acapy:8077/multitenancy/wallet/test-wallet").mock(
        return_value=httpx.Response(200)
    )

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller/webhooks",
        admin_url="http://acapy:8077",
        api_key="my-api-key",
        admin_api_key="admin-key",
        admin_api_key_name="x-api-key",
        http_client=http_client,
    )

    assert route.called
    assert route.calls.last.request.headers["x-api-key"] == "admin-key"


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_fallback_success(http_client):
    admin_route = respx.put("http://acapy/multitenancy/wallet/test-wallet").mock(
        return_value=httpx.Response(403, text="Forbidden")
    )
    tenant_route = respx.put("http://acapy/tenant/wallet").mock(
        return_value=httpx.Response(200)
    )

    mock_fetcher = AsyncMock(return_value="injected-token")

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
        token_fetcher=mock_fetcher,
    )

    assert admin_route.called
    assert tenant_route.called
    mock_fetcher.assert_called_once()
    assert (
        tenant_route.calls.last.request.headers["Authorization"]
        == "Bearer injected-token"
    )


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_traction_mode_direct_tenant_api(http_client):
    tenant_route = respx.put("http://acapy/tenant/wallet").mock(
        return_value=httpx.Response(200)
    )

    mock_fetcher = AsyncMock(return_value="traction-token")

    await register_tenant_webhook(
        wallet_id="ignored-in-traction-mode",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
        token_fetcher=mock_fetcher,
        use_admin_api=False,
    )

    assert tenant_route.call_count == 1
    assert (
        tenant_route.calls.last.request.headers["Authorization"]
        == "Bearer traction-token"
    )


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_no_fallback_without_fetcher(http_client):
    route = respx.put("http://acapy/multitenancy/wallet/test-wallet").mock(
        return_value=httpx.Response(403)
    )

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
        token_fetcher=None,
    )

    assert route.call_count == 1


@pytest.mark.asyncio
async def test_webhook_registration_missing_config(http_client):
    await register_tenant_webhook(
        wallet_id=None,
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
    )
    # Should return early without making any HTTP calls — no assertion needed beyond no exception


@pytest.mark.asyncio
async def test_webhook_registration_invalid_url(http_client):
    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="ftp://invalid-url",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
    )
    # Should return early without making any HTTP calls


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_retry_logic_with_backoff(http_client, mock_sleep):
    route = respx.put("http://acapy/multitenancy/wallet/test-wallet").mock(
        side_effect=[
            httpx.ConnectError("Not ready"),
            httpx.ConnectError("Still not ready"),
            httpx.Response(200),
        ]
    )

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
    )

    assert route.call_count == 3
    assert mock_sleep.call_count == 2
    mock_sleep.assert_has_calls([unittest.mock.call(2), unittest.mock.call(4)])


@pytest.mark.asyncio
async def test_startup_multi_tenant_injects_fetcher(mock_settings):
    mock_settings.ACAPY_TENANCY = "multi"
    mock_settings.ACAPY_TENANT_WALLET_KEY = "wallet-key"
    mock_settings.REDIS_MODE = "none"

    # Mock MultiTenantAcapy class to verify instantiation
    with (
        patch("api.main.init_db", new_callable=AsyncMock),
        patch("api.main.init_provider", new_callable=AsyncMock),
        patch("api.main.get_db", new_callable=AsyncMock),
        patch("api.main.MultiTenantAcapy") as mock_acapy_class,
        patch(
            "api.main.register_tenant_webhook", new_callable=AsyncMock
        ) as mock_register,
    ):
        # Setup mock instance
        mock_acapy_instance = MagicMock()
        mock_acapy_class.return_value = mock_acapy_instance
        mock_acapy_instance.get_wallet_token = "bound-method-ref"

        await on_tenant_startup()

        assert mock_register.called
        _, kwargs = mock_register.call_args
        assert kwargs["token_fetcher"] == "bound-method-ref"
        assert kwargs["use_admin_api"]


@pytest.mark.asyncio
async def test_startup_traction_mode_config(mock_settings):
    mock_settings.ACAPY_TENANCY = "traction"
    mock_settings.REDIS_MODE = "none"

    with (
        patch("api.main.init_db", new_callable=AsyncMock),
        patch("api.main.init_provider", new_callable=AsyncMock),
        patch("api.main.get_db", new_callable=AsyncMock),
        patch("api.main.TractionTenantAcapy") as mock_traction_class,
        patch(
            "api.main.register_tenant_webhook", new_callable=AsyncMock
        ) as mock_register,
    ):
        mock_traction_instance = MagicMock()
        mock_traction_class.return_value = mock_traction_instance
        mock_traction_instance.get_wallet_token = "traction-token-fetcher"

        await on_tenant_startup()

        assert mock_register.called
        _, kwargs = mock_register.call_args
        assert kwargs["token_fetcher"] == "traction-token-fetcher"
        assert not kwargs["use_admin_api"]


@pytest.mark.asyncio
async def test_startup_single_tenant_skips_registration(mock_settings):
    mock_settings.ACAPY_TENANCY = "single"
    mock_settings.REDIS_MODE = "none"

    with (
        patch("api.main.init_db", new_callable=AsyncMock),
        patch("api.main.init_provider", new_callable=AsyncMock),
        patch("api.main.get_db", new_callable=AsyncMock),
        patch(
            "api.main.register_tenant_webhook", new_callable=AsyncMock
        ) as mock_register,
    ):
        await on_tenant_startup()

        assert not mock_register.called


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_401_stops_immediately(http_client, mock_sleep):
    route = respx.put("http://acapy/multitenancy/wallet/test-wallet").mock(
        return_value=httpx.Response(401)
    )

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
    )

    assert route.call_count == 1
    mock_sleep.assert_not_called()


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_exhaust_retries(http_client, mock_sleep):
    respx.put("http://acapy/multitenancy/wallet/test-wallet").mock(
        side_effect=httpx.ConnectError("Down")
    )

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
    )

    # max_retries = 5
    assert respx.calls.call_count == 5


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_unexpected_exception(http_client, mock_sleep):
    respx.put("http://acapy/multitenancy/wallet/test-wallet").mock(
        side_effect=Exception("Something weird happened")
    )

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
    )

    assert respx.calls.call_count == 1
    mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_startup_redis_check_success(mock_settings):
    """Test startup logic verifies Redis connection if adapter enabled."""
    mock_settings.REDIS_MODE = "single"  # Enable Redis via REDIS_MODE

    with (
        patch("api.main.init_db", new_callable=AsyncMock),
        patch("api.main.init_provider", new_callable=AsyncMock),
        patch("api.main.get_db", new_callable=AsyncMock),
        patch("api.main.can_we_reach_redis", return_value=True) as mock_reach,
        patch("api.main.build_redis_url", return_value="redis://localhost"),
        patch("api.main.validate_redis_config"),
    ):
        await on_tenant_startup()

        mock_reach.assert_called_once_with("redis://localhost")


@pytest.mark.asyncio
async def test_startup_redis_check_failure(mock_settings):
    """Test startup fails fast when Redis is configured but unreachable."""
    mock_settings.REDIS_MODE = "single"  # Enable Redis via REDIS_MODE
    mock_settings.REDIS_HOST = "redis:6379"

    with (
        patch("api.main.init_db", new_callable=AsyncMock),
        patch("api.main.init_provider", new_callable=AsyncMock),
        patch("api.main.get_db", new_callable=AsyncMock),
        patch("api.main.can_we_reach_redis", return_value=False),
        patch("api.main.build_redis_url", return_value="redis://localhost"),
        patch("api.main.validate_redis_config"),
    ):
        with pytest.raises(
            RuntimeError,
            match="REDIS_MODE=single is configured but Redis is not reachable",
        ):
            await on_tenant_startup()


@pytest.mark.asyncio
async def test_webhook_registration_missing_webhook_url(http_client):
    await register_tenant_webhook(
        wallet_id="test",
        webhook_url="",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
    )


@pytest.mark.asyncio
async def test_webhook_registration_traction_mode_missing_fetcher(http_client):
    await register_tenant_webhook(
        wallet_id="ignored",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
        token_fetcher=None,
        use_admin_api=False,
    )


@pytest.mark.asyncio
@respx.mock
async def test_register_via_tenant_api_server_error(http_client):
    respx.put("http://acapy/tenant/wallet").mock(
        return_value=httpx.Response(500, text="Internal Error")
    )

    fetcher = AsyncMock(return_value="token")
    result = await _register_via_tenant_api("http://acapy", {}, fetcher, http_client)
    assert result is False


@pytest.mark.asyncio
@respx.mock
async def test_register_via_tenant_api_client_error(http_client):
    respx.put("http://acapy/tenant/wallet").mock(
        return_value=httpx.Response(400, text="Bad Request")
    )

    fetcher = AsyncMock(return_value="token")
    result = await _register_via_tenant_api("http://acapy", {}, fetcher, http_client)
    assert result is False


@pytest.mark.asyncio
@respx.mock
async def test_register_via_tenant_api_exception(http_client):
    respx.put("http://acapy/tenant/wallet").mock(side_effect=Exception("Network Down"))

    fetcher = AsyncMock(return_value="token")
    result = await _register_via_tenant_api("http://acapy", {}, fetcher, http_client)
    assert result is False


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_unexpected_status_code(http_client):
    route = respx.put("http://acapy/multitenancy/wallet/test-wallet").mock(
        return_value=httpx.Response(418)
    )

    await register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
        http_client=http_client,
        use_admin_api=True,
    )

    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_webhook_registration_masks_api_key_in_logs(http_client):
    respx.put("http://acapy/multitenancy/wallet/test-wallet").mock(
        return_value=httpx.Response(200)
    )

    with patch("api.core.webhook_utils.logger") as mock_logger:
        secret_key = "super-secret-key"
        base_url = "http://controller/webhooks"

        await register_tenant_webhook(
            wallet_id="test-wallet",
            webhook_url=base_url,
            admin_url="http://acapy",
            api_key=secret_key,
            admin_api_key=None,
            admin_api_key_name=None,
            http_client=http_client,
        )

        info_calls = [args[0] for args, _ in mock_logger.info.call_args_list]

        expected_log_fragment = f"{base_url}#*****"
        assert any(expected_log_fragment in call for call in info_calls)
        assert not any(secret_key in call for call in info_calls), (
            "SECRET KEY LEAKED IN LOGS!"
        )
