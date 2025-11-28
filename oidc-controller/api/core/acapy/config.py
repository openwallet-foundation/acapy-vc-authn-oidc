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
