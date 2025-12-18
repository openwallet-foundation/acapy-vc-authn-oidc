import requests
import structlog
import json
import time

from typing import Protocol

from ..config import settings

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


class AgentConfig(Protocol):
    def get_headers() -> dict[str, str]: ...


class MultiTenantAcapy:
    wallet_id = settings.ACAPY_TENANT_WALLET_ID
    wallet_key = settings.ACAPY_TENANT_WALLET_KEY

    # Class-level cache to share token across instances and manage expiry
    _token: str | None = None
    _token_expiry: float = 0.0
    # Refresh token every hour (safe for default 1-day expiry)
    TOKEN_TTL: int = settings.ACAPY_TOKEN_CACHE_TTL

    def get_wallet_token(self):
        # Check if valid token exists in cache
        now = time.time()
        if self._token and now < self._token_expiry:
            return self._token

        logger.debug(">>> get_wallet_token (Multi-Tenant Mode) - Fetching new token")

        if not self.wallet_id:
            raise ValueError("ACAPY_TENANT_WALLET_ID is required for multi-tenant mode")

        # Check if admin API key is configured
        admin_api_key_configured = (
            settings.ST_ACAPY_ADMIN_API_KEY_NAME and settings.ST_ACAPY_ADMIN_API_KEY
        )

        headers = {}

        if admin_api_key_configured:
            logger.debug("Admin API key is configured, adding to request headers")
            headers[settings.ST_ACAPY_ADMIN_API_KEY_NAME] = (
                settings.ST_ACAPY_ADMIN_API_KEY
            )
        else:
            logger.debug(
                "No admin API key configured, proceeding without authentication headers"
            )

        payload = {"wallet_key": self.wallet_key}

        resp_raw = requests.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{self.wallet_id}/token",
            headers=headers,
            json=payload,
        )

        if resp_raw.status_code != 200:
            error_detail = resp_raw.content.decode()
            logger.error(
                f"Failed to get wallet token. Status: {resp_raw.status_code}, Detail: {error_detail}"
            )
            # Raising Exception to be caught by the except block below or propagated
            raise Exception(f"{resp_raw.status_code}::{error_detail}")

        resp = json.loads(resp_raw.content)

        # Update class-level cache
        MultiTenantAcapy._token = resp["token"]
        MultiTenantAcapy._token_expiry = time.time() + self.TOKEN_TTL

        logger.debug("<<< get_wallet_token - Cached new token")
        return MultiTenantAcapy._token

    def get_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.get_wallet_token()}


class TractionTenantAcapy:
    """
    Configuration for Traction Multi-Tenancy.
    Uses unified ACAPY_TENANT_WALLET_* variables mapped to Traction Tenant ID and API Key.
    """

    # Map unified variables to Traction concepts
    tenant_id = settings.ACAPY_TENANT_WALLET_ID
    api_key = settings.ACAPY_TENANT_WALLET_KEY

    # Class-level cache
    _token: str | None = None
    _token_expiry: float = 0.0
    TOKEN_TTL: int = settings.ACAPY_TOKEN_CACHE_TTL

    def get_wallet_token(self):
        # Check if valid token exists in cache
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

        logger.debug(
            "Attempting Traction Token acquisition via tenant_id/api_key",
            tenant_id=self.tenant_id,
        )

        try:
            payload = {"api_key": self.api_key}
            resp_raw = requests.post(
                settings.ACAPY_ADMIN_URL
                + f"/multitenancy/tenant/{self.tenant_id}/token",
                json=payload,
            )

            if resp_raw.status_code == 200:
                resp = json.loads(resp_raw.content)

                # Update class-level cache
                TractionTenantAcapy._token = resp["token"]
                TractionTenantAcapy._token_expiry = time.time() + self.TOKEN_TTL

                logger.debug("<<< get_wallet_token (Success via Traction API)")
                return TractionTenantAcapy._token
            else:
                error_detail = resp_raw.content.decode()
                logger.error(
                    "Traction API Token fetch failed",
                    status=resp_raw.status_code,
                    detail=error_detail,
                )
                raise Exception(f"{resp_raw.status_code}::{error_detail}")

        except Exception as e:
            logger.error("Error connecting to Traction Tenant API", error=str(e))
            raise e

    def get_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.get_wallet_token()}


class SingleTenantAcapy:
    def get_headers(self) -> dict[str, str]:
        # Check if admin API key is configured
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
