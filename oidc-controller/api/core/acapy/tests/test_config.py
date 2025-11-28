import mock
import pytest
from api.core.acapy.config import MultiTenantAcapy, SingleTenantAcapy
from api.core.config import settings


@pytest.mark.asyncio
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY_NAME", "name")
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY", "key")
async def test_single_tenant_has_expected_headers_configured():
    acapy = SingleTenantAcapy()
    headers = acapy.get_headers()
    assert headers == {"name": "key"}


@pytest.mark.asyncio
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY_NAME", "name")
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY", None)
async def test_single_tenant_empty_headers_not_configured():
    # Test behavior when API key is missing
    acapy = SingleTenantAcapy()
    headers = acapy.get_headers()
    assert headers == {}


@pytest.mark.asyncio
async def test_multi_tenant_get_headers_returns_bearer_token_auth(requests_mock):
    acapy = MultiTenantAcapy()
    acapy.get_wallet_token = mock.MagicMock(return_value="token")
    headers = acapy.get_headers()
    assert headers == {"Authorization": "Bearer token"}


@pytest.mark.asyncio
async def test_multi_tenant_get_wallet_token_returns_token_at_token_key(requests_mock):
    wallet_id = "wallet_id"
    wallet_key = "wallet_key"

    with mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(settings, "MT_ACAPY_WALLET_KEY", wallet_key):

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            headers={},
            json={"token": "token"},
            status_code=200,
        )

        acapy = MultiTenantAcapy()
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        acapy.get_wallet_token.cache_clear()

        token = acapy.get_wallet_token()
        assert token == "token"


@pytest.mark.asyncio
async def test_multi_tenant_get_wallet_token_includes_auth_headers_and_body(
    requests_mock,
):
    # Verify headers and body payload
    wallet_id = "wallet_id"
    wallet_key = "wallet_key"
    admin_key = "admin_key"
    admin_header = "x-api-key"

    # Mock settings for the duration of this test
    with mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(
        settings, "MT_ACAPY_WALLET_KEY", wallet_key
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY", admin_key
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY_NAME", admin_header
    ):

        acapy = MultiTenantAcapy()
        # Ensure we use the values we expect (class init reads settings once)
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        # Ensure we bypass cache from any previous tests
        acapy.get_wallet_token.cache_clear()

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"token": "token"},
            status_code=200,
        )

        token = acapy.get_wallet_token()
        assert token == "token"

        # Verify request details
        last_request = requests_mock.last_request
        assert last_request.headers[admin_header] == admin_key
        assert last_request.json() == {"wallet_key": wallet_key}


@pytest.mark.asyncio
async def test_multi_tenant_get_wallet_token_no_auth_headers_when_not_configured(
    requests_mock,
):
    # Test insecure mode behavior
    wallet_id = "wallet_id"
    wallet_key = "wallet_key"

    # Mock settings with None for admin key
    with mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(
        settings, "MT_ACAPY_WALLET_KEY", wallet_key
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY", None
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY_NAME", "x-api-key"
    ):

        acapy = MultiTenantAcapy()
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        acapy.get_wallet_token.cache_clear()

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"token": "token"},
            status_code=200,
        )

        token = acapy.get_wallet_token()
        assert token == "token"

        # Verify request details
        last_request = requests_mock.last_request
        # Headers might contain Content-Type, but should not contain the api key
        assert "x-api-key" not in last_request.headers
        assert last_request.json() == {"wallet_key": wallet_key}


@pytest.mark.asyncio
async def test_multi_tenant_throws_exception_for_401_unauthorized(requests_mock):
    wallet_id = "wallet_id"
    wallet_key = "wallet_key"

    with mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(settings, "MT_ACAPY_WALLET_KEY", wallet_key):

        acapy = MultiTenantAcapy()
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        acapy.get_wallet_token.cache_clear()

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"error": "unauthorized"},
            status_code=401,
        )

        # Check for generic Exception, as the code now raises Exception(f"{code}::{detail}")
        with pytest.raises(Exception) as excinfo:
            acapy.get_wallet_token()

        assert "401" in str(excinfo.value)
        assert "unauthorized" in str(excinfo.value)
