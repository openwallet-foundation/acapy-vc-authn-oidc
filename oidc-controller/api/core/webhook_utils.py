import asyncio
import structlog
import requests
from typing import Callable


logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


async def register_tenant_webhook(
    wallet_id: str,
    webhook_url: str,
    admin_url: str,
    api_key: str | None,
    admin_api_key: str | None,
    admin_api_key_name: str | None,
    token_fetcher: Callable[[], str] | None = None,
):
    """
    Registers the controller's webhook URL with the ACA-Py Agent Tenant.
    Strategy:
    1. Try the Admin API (`/multitenancy/wallet/{id}`).
    2. If that fails with 403/404 (Blocked) and wallet_key is present,
       fallback to the Tenant API (`/tenant/wallet`).
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
    base_delay = 2  # seconds

    logger.info(f"Attempting to register webhook for wallet {wallet_id}...")

    for attempt in range(0, max_retries):
        try:
            # Try Admin API
            response = requests.put(
                target_url, json=payload, headers=headers, timeout=5
            )

            if response.status_code == 200:
                logger.info("Successfully registered webhook URL with ACA-Py tenant")
                return

            # Fallback Logic: If Admin API is blocked (403/404)
            elif response.status_code in [403, 404] and token_fetcher:
                logger.info(
                    f"Admin API returned {response.status_code}. Attempting Tenant API fallback..."
                )
                if await _register_via_tenant_api(admin_url, payload, token_fetcher):
                    return
                # If fallback fails, stop (don't retry admin api)
                return

            elif response.status_code == 401:
                logger.error("Admin API Unauthorized (401). Check ADMIN_API_KEY.")
                return

            elif response.status_code >= 500:
                # Retry on server errors
                logger.warning(
                    f"Webhook registration failed with server error {response.status_code}: {response.text}. Retrying..."
                )

            else:
                logger.warning(
                    f"Webhook registration returned status {response.status_code}: {response.text}"
                )
                return

        except requests.exceptions.ConnectionError:
            logger.warning(f"ACA-Py Agent unreachable at {admin_url}")
        except Exception as e:
            logger.error(f"Unexpected error during webhook registration: {str(e)}")
            return

        if attempt < max_retries - 1:
            delay = base_delay * (2**attempt)
            logger.debug(
                f"Retrying webhook registration in {delay} seconds (Attempt {attempt + 1}/{max_retries})"
            )
            await asyncio.sleep(delay)

    logger.error(
        "Failed to register webhook after multiple attempts. Agent notification may fail."
    )


async def _register_via_tenant_api(
    admin_url: str, payload: dict, token_fetcher: Callable[[], str]
) -> bool:
    """Fallback: use /tenant/wallet endpoint with provided token fetcher."""
    try:
        # 1. Get Token
        token = token_fetcher()

        if not token:
            logger.error("Tenant Fallback: Token fetcher returned empty token")
            return False

        # 2. Update via Tenant API
        # Using the standard Traction/ACA-Py Tenant endpoint
        tenant_url = f"{admin_url}/tenant/wallet"
        tenant_headers = {"Authorization": f"Bearer {token}"}

        update_res = requests.put(
            tenant_url, json=payload, headers=tenant_headers, timeout=5
        )

        if update_res.status_code == 200:
            logger.info("Successfully registered webhook via Tenant API")
            return True
        else:
            logger.error(
                f"Tenant Fallback: Update failed. Status: {update_res.status_code} Body: {update_res.text}"
            )
            return False

    except Exception as e:
        logger.error(f"Tenant Fallback Exception: {e}")
        return False
