import asyncio
import structlog
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


async def register_tenant_webhook(
    wallet_id: str,
    webhook_url: str,
    admin_url: str,
    api_key: str | None,
    admin_api_key: str | None,
    admin_api_key_name: str | None,
):
    """
    Registers the controller's webhook URL with the ACA-Py Agent Tenant.
    Includes retries for agent startup and validation for configuration.
    """
    if not webhook_url or not wallet_id:
        logger.warning(
            "Multi-tenant mode enabled but CONTROLLER_WEB_HOOK_URL or MT_ACAPY_WALLET_ID is missing. "
            "Verification callbacks may not work."
        )
        return

    if not webhook_url.startswith("http"):
        logger.error(
            f"Invalid webhook URL format: {webhook_url}. Must start with http:// or https://"
        )
        return

    # Prepare URL with Authentication
    # Ensure API key is in the URL if configured.
    # ACA-Py supports this by appending #key to the URL
    if api_key and "#" not in webhook_url:
        webhook_url = f"{webhook_url}#{api_key}"

    headers = {}
    if admin_api_key_name and admin_api_key:
        headers[admin_api_key_name] = admin_api_key

    target_url = f"{admin_url}/multitenancy/wallet/{wallet_id}"
    payload = {"wallet_webhook_urls": [webhook_url]}

    max_retries = 5
    retry_delay = 2  # seconds

    logger.info(f"Attempting to register webhook for wallet {wallet_id}...")

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.put(
                target_url, json=payload, headers=headers, timeout=5
            )

            if response.status_code == 200:
                logger.info("Successfully registered webhook URL with ACA-Py tenant")
                return
            elif response.status_code in [401, 403]:
                logger.error(
                    f"Webhook registration failed: Unauthorized (401/403). Check AGENT_ADMIN_API_KEY configuration."
                )
                return
            else:
                logger.warning(
                    f"Webhook registration returned status {response.status_code}: {response.text}"
                )

        except requests.exceptions.ConnectionError:
            logger.warning(
                f"ACA-Py Agent unreachable at {admin_url} (Attempt {attempt}/{max_retries})"
            )
        except Exception as e:
            logger.error(f"Unexpected error during webhook registration: {str(e)}")
            return

        if attempt < max_retries:
            await asyncio.sleep(retry_delay)

    logger.error(
        "Failed to register webhook after multiple attempts. Agent notification may fail."
    )
