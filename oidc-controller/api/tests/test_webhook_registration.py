import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import requests
from api.main import _register_tenant_webhook

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import requests
from api.main import _register_tenant_webhook


@pytest.fixture
def mock_requests_put():
    """Mock requests.put."""
    with patch("api.main.requests.put") as mock:
        yield mock


@pytest.fixture
def mock_sleep():
    """Mock asyncio.sleep to prevent slow tests."""
    with patch("api.main.asyncio.sleep", new_callable=AsyncMock) as mock:
        yield mock


@pytest.mark.asyncio
async def test_webhook_registration_success(mock_requests_put):
    """Test successful webhook registration with API key injection."""
    mock_requests_put.return_value.status_code = 200

    await _register_tenant_webhook(
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
    await _register_tenant_webhook(
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
    await _register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="ftp://invalid-url",  # Invalid protocol
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )

    mock_requests_put.assert_not_called()


@pytest.mark.asyncio
async def test_webhook_registration_retry_logic(mock_requests_put, mock_sleep):
    """Test that the function retries on connection error and eventually succeeds."""
    # Fail twice with ConnectionError, then succeed
    mock_requests_put.side_effect = [
        requests.exceptions.ConnectionError("Not ready"),
        requests.exceptions.ConnectionError("Still not ready"),
        MagicMock(status_code=200),
    ]

    await _register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )

    assert mock_requests_put.call_count == 3
    assert mock_sleep.call_count == 2  # Slept twice between 3 attempts


@pytest.mark.asyncio
async def test_webhook_registration_fatal_auth_error(mock_requests_put, mock_sleep):
    """Test that 401/403 errors stop retries immediately."""
    mock_requests_put.return_value.status_code = 401  # Unauthorized

    await _register_tenant_webhook(
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

    await _register_tenant_webhook(
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

    await _register_tenant_webhook(
        wallet_id="test-wallet",
        webhook_url="http://controller",
        admin_url="http://acapy",
        api_key=None,
        admin_api_key=None,
        admin_api_key_name=None,
    )

    assert mock_requests_put.call_count == 1
    mock_sleep.assert_not_called()
