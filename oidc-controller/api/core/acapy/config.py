import requests
import structlog
import json

from functools import cache
from typing import Protocol

from ..config import settings

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


class AgentConfig(Protocol):
    def get_headers() -> dict[str, str]: ...


class MultiTenantAcapy:
    wallet_id = settings.MT_ACAPY_WALLET_ID
    wallet_key = settings.MT_ACAPY_WALLET_KEY

    @cache
    def get_wallet_token(self):
        logger.debug(">>> get_wallet_token")

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
        wallet_token = resp["token"]

        logger.debug("<<< get_wallet_token")
        return wallet_token

    def get_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.get_wallet_token()}


class TractionTenantAcapy:
    """
    Configuration for Traction Multi-Tenancy.
    Attempts to fetch a token using Traction Tenant API credentials first.
    Falls back to ACA-Py Wallet Key authentication if Traction credentials are not set.
    """

    tenant_id = settings.TRACTION_TENANT_ID
    tenant_api_key = settings.TRACTION_TENANT_API_KEY
    wallet_id = settings.MT_ACAPY_WALLET_ID
    wallet_key = settings.MT_ACAPY_WALLET_KEY

    @cache
    def get_wallet_token(self):
        logger.debug(">>> get_wallet_token (Traction Mode)")

        # Try Traction API Key Flow
        if self.tenant_id and self.tenant_api_key:
            logger.debug(
                "Attempting Traction Token acquisition via tenant_id/api_key",
                tenant_id=self.tenant_id,
            )
            try:
                payload = {"api_key": self.tenant_api_key}
                resp_raw = requests.post(
                    settings.ACAPY_ADMIN_URL
                    + f"/multitenancy/tenant/{self.tenant_id}/token",
                    json=payload,
                )

                if resp_raw.status_code == 200:
                    resp = json.loads(resp_raw.content)
                    logger.debug("<<< get_wallet_token (Success via Traction API)")
                    return resp["token"]
                else:
                    logger.warning(
                        "Traction API Token fetch failed",
                        status=resp_raw.status_code,
                        detail=resp_raw.content.decode(),
                    )
            except Exception as e:
                logger.error("Error connecting to Traction Tenant API", error=str(e))

        # Fallback to Standard ACA-Py Wallet Key Flow
        if self.wallet_id and self.wallet_key:
            logger.debug(
                "Attempting Wallet Token acquisition via wallet_id/wallet_key",
                wallet_id=self.wallet_id,
            )
            try:
                # No Admin Headers in Traction mode as we assume Admin API is blocked
                payload = {"wallet_key": self.wallet_key}
                resp_raw = requests.post(
                    settings.ACAPY_ADMIN_URL
                    + f"/multitenancy/wallet/{self.wallet_id}/token",
                    json=payload,
                )

                if resp_raw.status_code == 200:
                    resp = json.loads(resp_raw.content)
                    logger.debug("<<< get_wallet_token (Success via Wallet Key)")
                    return resp["token"]
                else:
                    error_detail = resp_raw.content.decode()
                    logger.error(
                        f"Failed to get wallet token via wallet key fallback. Status: {resp_raw.status_code}, Detail: {error_detail}"
                    )
                    raise Exception(f"{resp_raw.status_code}::{error_detail}")

            except Exception as e:
                logger.error("Error fetching token via wallet key", error=str(e))
                raise e

        # No valid credentials found
        error_msg = "Could not acquire token. Ensure TRACTION_TENANT_ID/API_KEY or MT_ACAPY_WALLET_ID/KEY are set."
        logger.error(error_msg)
        raise Exception(error_msg)

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
