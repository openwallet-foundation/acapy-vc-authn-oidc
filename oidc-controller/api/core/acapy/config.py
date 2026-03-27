import asyncio
import time
from typing import Protocol

import httpx
import structlog

from ..config import settings

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


class AgentConfig(Protocol):
    async def get_headers(self) -> dict[str, str]: ...


class MultiTenantAcapy:
    wallet_id = settings.ACAPY_TENANT_WALLET_ID
    wallet_key = settings.ACAPY_TENANT_WALLET_KEY

    # Class-level cache shared across instances (token is per-wallet, not per-instance)
    _token: str | None = None
    _token_expiry: float = 0.0
    TOKEN_TTL: int = settings.ACAPY_TOKEN_CACHE_TTL
    # Lock prevents thundering herd on concurrent token refresh
    _token_lock: asyncio.Lock = asyncio.Lock()

    def __init__(self, http_client: httpx.AsyncClient):
        self._http_client = http_client

    async def get_wallet_token(self) -> str:
        # Fast path — check without lock first
        now = time.time()
        if self._token and now < self._token_expiry:
            return self._token

        async with MultiTenantAcapy._token_lock:
            # Double-check: another coroutine may have refreshed while we waited
            now = time.time()
            if self._token and now < self._token_expiry:
                return self._token

            logger.debug(
                ">>> get_wallet_token (Multi-Tenant Mode) - Fetching new token"
            )

            if not self.wallet_id:
                raise ValueError(
                    "ACAPY_TENANT_WALLET_ID is required for multi-tenant mode"
                )

            admin_api_key_configured = (
                settings.ST_ACAPY_ADMIN_API_KEY_NAME and settings.ST_ACAPY_ADMIN_API_KEY
            )

            headers = {}
            if admin_api_key_configured:
                headers[settings.ST_ACAPY_ADMIN_API_KEY_NAME] = (
                    settings.ST_ACAPY_ADMIN_API_KEY
                )

            resp = await self._http_client.post(
                settings.ACAPY_ADMIN_URL
                + f"/multitenancy/wallet/{self.wallet_id}/token",
                headers=headers,
                json={"wallet_key": self.wallet_key},
            )

            if resp.status_code != 200:
                error_detail = resp.content.decode()
                logger.error(
                    f"Failed to get wallet token. Status: {resp.status_code}, Detail: {error_detail}"
                )
                raise Exception(f"{resp.status_code}::{error_detail}")

            MultiTenantAcapy._token = resp.json()["token"]
            MultiTenantAcapy._token_expiry = time.time() + self.TOKEN_TTL

            logger.debug("<<< get_wallet_token - Cached new token")
            return MultiTenantAcapy._token

    async def get_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + await self.get_wallet_token()}


class TractionTenantAcapy:
    """
    Configuration for Traction Multi-Tenancy.
    Uses unified ACAPY_TENANT_WALLET_* variables mapped to Traction Tenant ID and API Key.
    """

    tenant_id = settings.ACAPY_TENANT_WALLET_ID
    api_key = settings.ACAPY_TENANT_WALLET_KEY

    _token: str | None = None
    _token_expiry: float = 0.0
    TOKEN_TTL: int = settings.ACAPY_TOKEN_CACHE_TTL
    _token_lock: asyncio.Lock = asyncio.Lock()

    def __init__(self, http_client: httpx.AsyncClient):
        self._http_client = http_client

    async def get_wallet_token(self) -> str:
        # Fast path — check without lock first
        now = time.time()
        if self._token and now < self._token_expiry:
            return self._token

        async with TractionTenantAcapy._token_lock:
            # Double-check after acquiring lock
            now = time.time()
            if self._token and now < self._token_expiry:
                return self._token

            logger.debug(">>> get_wallet_token (Traction Mode) - Fetching new token")

            if not self.tenant_id or not self.api_key:
                error_msg = (
                    "Traction mode requires ACAPY_TENANT_WALLET_ID (Tenant ID) "
                    "and ACAPY_TENANT_WALLET_KEY (API Key) to be set."
                )
                logger.error(error_msg)
                raise ValueError(error_msg)

            try:
                resp = await self._http_client.post(
                    settings.ACAPY_ADMIN_URL
                    + f"/multitenancy/tenant/{self.tenant_id}/token",
                    json={"api_key": self.api_key},
                )

                if resp.status_code == 200:
                    TractionTenantAcapy._token = resp.json()["token"]
                    TractionTenantAcapy._token_expiry = time.time() + self.TOKEN_TTL
                    logger.debug("<<< get_wallet_token (Success via Traction API)")
                    return TractionTenantAcapy._token
                else:
                    error_detail = resp.content.decode()
                    logger.error(
                        "Traction API Token fetch failed",
                        status=resp.status_code,
                        detail=error_detail,
                    )
                    raise Exception(f"{resp.status_code}::{error_detail}")

            except Exception as e:
                logger.error("Error connecting to Traction Tenant API", error=str(e))
                raise e

    async def get_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + await self.get_wallet_token()}


class SingleTenantAcapy:
    def __init__(self, http_client: httpx.AsyncClient):
        pass  # No HTTP calls needed for single-tenant header construction

    async def get_headers(self) -> dict[str, str]:
        admin_api_key_configured = (
            settings.ST_ACAPY_ADMIN_API_KEY_NAME and settings.ST_ACAPY_ADMIN_API_KEY
        )

        if admin_api_key_configured:
            return {
                settings.ST_ACAPY_ADMIN_API_KEY_NAME: settings.ST_ACAPY_ADMIN_API_KEY
            }
        else:
            logger.debug("No admin API key configured for single tenant agent")
            return {}
