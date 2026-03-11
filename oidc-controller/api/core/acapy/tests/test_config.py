import asyncio
import time
from unittest import mock

import httpx
import pytest
import respx
from api.core.acapy.config import (
    MultiTenantAcapy,
    SingleTenantAcapy,
    TractionTenantAcapy,
)
from api.core.config import settings


def reset_acapy_cache(cls):
    cls._token = None
    cls._token_expiry = 0.0


@pytest.fixture(autouse=True)
def clean_cache():
    """Ensure cache and lock state are clean before each test."""
    reset_acapy_cache(MultiTenantAcapy)
    reset_acapy_cache(TractionTenantAcapy)
    # Replace locks so a test that fails while holding one doesn't deadlock the next
    MultiTenantAcapy._token_lock = asyncio.Lock()
    TractionTenantAcapy._token_lock = asyncio.Lock()
    yield
    reset_acapy_cache(MultiTenantAcapy)
    reset_acapy_cache(TractionTenantAcapy)
    MultiTenantAcapy._token_lock = asyncio.Lock()
    TractionTenantAcapy._token_lock = asyncio.Lock()


@pytest.fixture
def http_client():
    return httpx.AsyncClient()


# ==========================================
# Single Tenant Tests
# ==========================================


@pytest.mark.asyncio
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY_NAME", "name")
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY", "key")
async def test_single_tenant_has_expected_headers_configured(http_client):
    acapy = SingleTenantAcapy(http_client)
    headers = await acapy.get_headers()
    assert headers == {"name": "key"}


@pytest.mark.asyncio
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY_NAME", "name")
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY", None)
async def test_single_tenant_empty_headers_not_configured(http_client):
    acapy = SingleTenantAcapy(http_client)
    headers = await acapy.get_headers()
    assert headers == {}


# ==========================================
# Multi-Tenant Tests
# ==========================================


@pytest.mark.asyncio
async def test_multi_tenant_get_headers_returns_bearer_token_auth(http_client):
    acapy = MultiTenantAcapy(http_client)
    acapy.get_wallet_token = mock.AsyncMock(return_value="token")

    headers = await acapy.get_headers()
    assert headers == {"Authorization": "Bearer token"}


@pytest.mark.asyncio
@respx.mock
async def test_multi_tenant_uses_unified_variables(http_client):
    wallet_id = "unified-wallet-id"
    wallet_key = "unified-wallet-key"

    # Patch class attributes directly because they are bound at module import time
    with (
        mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id),
        mock.patch.object(MultiTenantAcapy, "wallet_key", wallet_key),
    ):
        respx.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token"
        ).mock(return_value=httpx.Response(200, json={"token": "token"}))

        acapy = MultiTenantAcapy(http_client)

        token = await acapy.get_wallet_token()
        assert token == "token"


@pytest.mark.asyncio
async def test_multi_tenant_missing_id_raises_error(http_client):
    with mock.patch.object(MultiTenantAcapy, "wallet_id", None):
        acapy = MultiTenantAcapy(http_client)
        with pytest.raises(ValueError) as exc:
            await acapy.get_wallet_token()
        assert "ACAPY_TENANT_WALLET_ID is required" in str(exc.value)


@pytest.mark.asyncio
@respx.mock
async def test_multi_tenant_includes_admin_api_key_headers(http_client):
    wallet_id = "test-wallet-id"
    wallet_key = "test-wallet-key"
    admin_key = "admin_key"
    admin_header = "x-api-key"

    with (
        mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id),
        mock.patch.object(MultiTenantAcapy, "wallet_key", wallet_key),
        mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY", admin_key),
        mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY_NAME", admin_header),
    ):
        route = respx.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token"
        ).mock(return_value=httpx.Response(200, json={"token": "token"}))

        acapy = MultiTenantAcapy(http_client)
        token = await acapy.get_wallet_token()
        assert token == "token"
        assert route.calls.last.request.headers[admin_header] == admin_key


@pytest.mark.asyncio
@respx.mock
async def test_multi_tenant_caching_behavior(http_client):
    wallet_id = "cache-test-id"
    wallet_key = "cache-test-key"

    with (
        mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id),
        mock.patch.object(MultiTenantAcapy, "wallet_key", wallet_key),
    ):
        route = respx.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token"
        ).mock(return_value=httpx.Response(200, json={"token": "cached-token"}))

        acapy = MultiTenantAcapy(http_client)

        token1 = await acapy.get_wallet_token()
        assert token1 == "cached-token"
        assert route.call_count == 1

        token2 = await acapy.get_wallet_token()
        assert token2 == "cached-token"
        assert route.call_count == 1  # Should not increase


@pytest.mark.asyncio
@respx.mock
async def test_multi_tenant_token_expiry(http_client):
    wallet_id = "expiry-test-id"
    wallet_key = "expiry-test-key"

    with (
        mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id),
        mock.patch.object(MultiTenantAcapy, "wallet_key", wallet_key),
    ):
        route = respx.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token"
        ).mock(return_value=httpx.Response(200, json={"token": "fresh-token"}))

        acapy = MultiTenantAcapy(http_client)

        MultiTenantAcapy._token = "stale-token"
        MultiTenantAcapy._token_expiry = time.time() - 100  # Expired

        token = await acapy.get_wallet_token()
        assert token == "fresh-token"
        assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_multi_tenant_throws_exception_for_401(http_client):
    wallet_id = "test-wallet-id"
    wallet_key = "test-wallet-key"

    with (
        mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id),
        mock.patch.object(MultiTenantAcapy, "wallet_key", wallet_key),
    ):
        respx.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token"
        ).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))

        acapy = MultiTenantAcapy(http_client)
        with pytest.raises(Exception) as excinfo:
            await acapy.get_wallet_token()

        assert "401" in str(excinfo.value)


# ==========================================
# Traction Tenant Mode Tests
# ==========================================


@pytest.mark.asyncio
@respx.mock
async def test_traction_mode_uses_unified_variables_as_tenant_creds(http_client):
    import json as json_mod

    tenant_id = "unified-tenant-id"
    api_key = "unified-api-key"

    # TractionTenantAcapy reads from settings at class level
    with (
        mock.patch.object(TractionTenantAcapy, "tenant_id", tenant_id),
        mock.patch.object(TractionTenantAcapy, "api_key", api_key),
    ):
        # Verify calls /multitenancy/tenant/{id}/token (Traction API)
        route = respx.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token"
        ).mock(return_value=httpx.Response(200, json={"token": "traction-token"}))

        acapy = TractionTenantAcapy(http_client)

        token = await acapy.get_wallet_token()
        assert token == "traction-token"

        body = json_mod.loads(route.calls.last.request.content)
        assert body == {"api_key": api_key}


@pytest.mark.asyncio
@respx.mock
async def test_traction_caching_and_expiry(http_client):
    tenant_id = "traction-cache-id"
    api_key = "traction-cache-key"

    with (
        mock.patch.object(TractionTenantAcapy, "tenant_id", tenant_id),
        mock.patch.object(TractionTenantAcapy, "api_key", api_key),
    ):
        route = respx.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token"
        ).mock(return_value=httpx.Response(200, json={"token": "traction-token"}))

        acapy = TractionTenantAcapy(http_client)

        t1 = await acapy.get_wallet_token()
        assert t1 == "traction-token"
        assert route.call_count == 1

        t2 = await acapy.get_wallet_token()
        assert t2 == "traction-token"
        assert route.call_count == 1  # Cached

        TractionTenantAcapy._token_expiry = time.time() - 1

        t3 = await acapy.get_wallet_token()
        assert t3 == "traction-token"
        assert route.call_count == 2  # Refreshed


@pytest.mark.asyncio
async def test_traction_mode_missing_credentials_raises_error(http_client):
    """Test that missing credentials in Traction mode raises ValueError."""

    with (
        mock.patch.object(TractionTenantAcapy, "tenant_id", None),
        mock.patch.object(TractionTenantAcapy, "api_key", None),
    ):
        acapy = TractionTenantAcapy(http_client)

        with pytest.raises(ValueError) as exc:
            await acapy.get_wallet_token()
        assert "Traction mode requires ACAPY_TENANT_WALLET_ID" in str(exc.value)


@pytest.mark.asyncio
@respx.mock
async def test_traction_mode_api_failure_raises_exception(http_client):
    tenant_id = "test-tenant"
    api_key = "test-key"

    with (
        mock.patch.object(TractionTenantAcapy, "tenant_id", tenant_id),
        mock.patch.object(TractionTenantAcapy, "api_key", api_key),
    ):
        respx.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token"
        ).mock(return_value=httpx.Response(403, text="Forbidden"))

        acapy = TractionTenantAcapy(http_client)

        with pytest.raises(Exception) as exc:
            await acapy.get_wallet_token()
        assert "403" in str(exc.value)


@pytest.mark.asyncio
@respx.mock
async def test_traction_mode_connection_error_raises_exception(http_client):
    tenant_id = "test-tenant"
    api_key = "test-key"

    with (
        mock.patch.object(TractionTenantAcapy, "tenant_id", tenant_id),
        mock.patch.object(TractionTenantAcapy, "api_key", api_key),
    ):
        respx.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token"
        ).mock(side_effect=httpx.ConnectError("Connection refused"))

        acapy = TractionTenantAcapy(http_client)

        with pytest.raises(Exception):
            await acapy.get_wallet_token()


# ==========================================
# Concurrent / Race Condition Tests
# ==========================================


@pytest.mark.asyncio
async def test_multi_tenant_concurrent_calls_only_one_token_request():
    """Thundering herd: N concurrent calls with an expired token fire only 1 HTTP request.

    The lock prevents multiple coroutines from all fetching a new token simultaneously.
    The double-check inside the lock ensures waiters reuse the token fetched by the winner.
    """
    call_count = 0

    async def mock_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(
            0
        )  # Yield so other coroutines queue up waiting for the lock
        return httpx.Response(200, json={"token": "herd-token"})

    mock_client = mock.MagicMock()
    mock_client.post = mock_post

    with (
        mock.patch.object(MultiTenantAcapy, "wallet_id", "herd-wallet"),
        mock.patch.object(MultiTenantAcapy, "wallet_key", "herd-key"),
    ):
        acapy = MultiTenantAcapy(mock_client)
        results = await asyncio.gather(*[acapy.get_wallet_token() for _ in range(10)])

    assert all(t == "herd-token" for t in results)
    assert call_count == 1  # Only one HTTP request despite 10 concurrent callers


@pytest.mark.asyncio
async def test_multi_tenant_lock_released_after_failed_request():
    """If the token fetch raises an exception the lock is released.

    Subsequent calls must be able to acquire the lock and retry — not deadlock.
    """
    responses = iter(
        [
            httpx.Response(500, text="Server Error"),
            httpx.Response(200, json={"token": "retry-token"}),
        ]
    )

    mock_client = mock.MagicMock()
    mock_client.post = mock.AsyncMock(side_effect=lambda *a, **kw: next(responses))

    with (
        mock.patch.object(MultiTenantAcapy, "wallet_id", "fail-wallet"),
        mock.patch.object(MultiTenantAcapy, "wallet_key", "fail-key"),
    ):
        acapy = MultiTenantAcapy(mock_client)

        with pytest.raises(Exception) as exc:
            await acapy.get_wallet_token()
        assert "500" in str(exc.value)

        # Lock must be released — this must not deadlock
        token = await acapy.get_wallet_token()
        assert token == "retry-token"
        assert mock_client.post.call_count == 2


@pytest.mark.asyncio
async def test_multi_tenant_valid_token_bypasses_lock():
    """Callers with a valid cached token skip the lock entirely.

    Even when another coroutine holds the lock (mid-refresh), callers with a
    still-valid token must return immediately via the fast path.
    """
    async with httpx.AsyncClient() as http_client:
        with (
            mock.patch.object(MultiTenantAcapy, "wallet_id", "bypass-id"),
            mock.patch.object(MultiTenantAcapy, "wallet_key", "bypass-key"),
        ):
            MultiTenantAcapy._token = "valid-cached-token"
            MultiTenantAcapy._token_expiry = time.time() + 1000

            acapy = MultiTenantAcapy(http_client)

            # Simulate another coroutine holding the lock mid-refresh
            await MultiTenantAcapy._token_lock.acquire()
            try:
                # Fast path: valid token returned immediately without waiting for the lock
                token = await acapy.get_wallet_token()
            finally:
                MultiTenantAcapy._token_lock.release()

    assert token == "valid-cached-token"


@pytest.mark.asyncio
async def test_traction_concurrent_calls_only_one_token_request():
    """Thundering herd: N concurrent calls with an expired token fire only 1 HTTP request."""
    call_count = 0

    async def mock_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(
            0
        )  # Yield so other coroutines queue up waiting for the lock
        return httpx.Response(200, json={"token": "traction-herd-token"})

    mock_client = mock.MagicMock()
    mock_client.post = mock_post

    with (
        mock.patch.object(TractionTenantAcapy, "tenant_id", "herd-tenant"),
        mock.patch.object(TractionTenantAcapy, "api_key", "herd-key"),
    ):
        acapy = TractionTenantAcapy(mock_client)
        results = await asyncio.gather(*[acapy.get_wallet_token() for _ in range(10)])

    assert all(t == "traction-herd-token" for t in results)
    assert call_count == 1


@pytest.mark.asyncio
async def test_traction_lock_released_after_failed_request():
    """If the Traction token fetch raises an exception the lock is released.

    Subsequent calls must be able to acquire the lock and retry — not deadlock.
    """
    responses = iter(
        [
            httpx.Response(500, text="Server Error"),
            httpx.Response(200, json={"token": "traction-retry-token"}),
        ]
    )

    mock_client = mock.MagicMock()
    mock_client.post = mock.AsyncMock(side_effect=lambda *a, **kw: next(responses))

    with (
        mock.patch.object(TractionTenantAcapy, "tenant_id", "fail-tenant"),
        mock.patch.object(TractionTenantAcapy, "api_key", "fail-key"),
    ):
        acapy = TractionTenantAcapy(mock_client)

        with pytest.raises(Exception) as exc:
            await acapy.get_wallet_token()
        assert "500" in str(exc.value)

        # Lock must be released — this must not deadlock
        token = await acapy.get_wallet_token()
        assert token == "traction-retry-token"
        assert mock_client.post.call_count == 2


def test_token_ttl_configuration():
    assert MultiTenantAcapy.TOKEN_TTL == 3600
    assert TractionTenantAcapy.TOKEN_TTL == 3600

    original_ttl = MultiTenantAcapy.TOKEN_TTL
    try:
        MultiTenantAcapy.TOKEN_TTL = 300
        assert MultiTenantAcapy.TOKEN_TTL == 300
        http_client = httpx.AsyncClient()
        acapy = MultiTenantAcapy(http_client)
        assert acapy.TOKEN_TTL == 300
    finally:
        MultiTenantAcapy.TOKEN_TTL = original_ttl
