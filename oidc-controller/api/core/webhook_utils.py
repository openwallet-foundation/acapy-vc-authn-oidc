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
    use_admin_api: bool = True,
):
    """
    Registers the controller's webhook URL with the ACA-Py Agent Tenant.

    Strategies:
    1. If use_admin_api is True (default for 'multi' mode):
       - Try the Admin API (`/multitenancy/wallet/{id}`).
       - If that fails with 403/404 (Blocked) and token_fetcher is present,
         fallback to the Tenant API (`/tenant/wallet`).

    2. If use_admin_api is False (default for 'traction' mode):
       - Directly fetch token using token_fetcher.
       - Use Tenant API (`/tenant/wallet`) to update webhook.
    """
    if not webhook_url:
        logger.warning(
            "Webhook registration skipped: CONTROLLER_WEB_HOOK_URL is missing. "
            "Verification callbacks may not work."
        )
        return

    if use_admin_api and not wallet_id:
        logger.error("Admin API registration requested but wallet_id is missing.")
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

    payload = {"wallet_webhook_urls": [webhook_url]}

    max_retries = 5
    base_delay = 2  # seconds

    logger.info(f"Attempting to register webhook: {webhook_url}")

    for attempt in range(0, max_retries):
        try:
            # STRATEGY 1: Standard Multi-Tenant Admin API
            if use_admin_api:
                headers = {}
                if admin_api_key_name and admin_api_key:
                    headers[admin_api_key_name] = admin_api_key

                target_url = f"{admin_url}/multitenancy/wallet/{wallet_id}"
                logger.debug(f"Attempting Admin API update at {target_url}")

                response = requests.put(
                    target_url, json=payload, headers=headers, timeout=5
                )

                if response.status_code == 200:
                    logger.info(
                        "Successfully registered webhook URL with ACA-Py tenant via Admin API"
                    )
                    return

                # Fallback Logic: If Admin API is blocked (403/404)
                elif response.status_code in [403, 404]:
                    logger.warning(
                        f"Admin API returned {response.status_code}. Checking for Tenant API fallback capability..."
                    )
                    if token_fetcher:
                        if await _register_via_tenant_api(
                            admin_url, payload, token_fetcher
                        ):
                            return
                    else:
                        logger.error(
                            "Cannot fallback to Tenant API: No token fetcher available."
                        )
                        return

                elif response.status_code == 401:
                    logger.error("Admin API Unauthorized (401). Check ADMIN_API_KEY.")
                    return

                elif response.status_code >= 500:
                    logger.warning(
                        f"Webhook registration failed with server error {response.status_code}: {response.text}. Retrying..."
                    )
                else:
                    logger.warning(
                        f"Webhook registration returned unexpected status {response.status_code}: {response.text}"
                    )
                    return

            # STRATEGY 2: Direct Tenant API (Traction Mode)
            else:
                if not token_fetcher:
                    logger.error(
                        "Direct Tenant API registration requested but no token_fetcher provided."
                    )
                    return

                logger.debug("Attempting Direct Tenant API update")
                if await _register_via_tenant_api(admin_url, payload, token_fetcher):
                    return
                logger.warning("Direct Tenant API update failed. Retrying...")

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
    """Fallback/Direct: use /tenant/wallet endpoint with provided token fetcher."""
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
        elif update_res.status_code >= 500:
            logger.warning(
                f"Tenant API Server Error: {update_res.status_code}. {update_res.text}"
            )
            return False
        else:
            logger.error(
                f"Tenant API Update failed. Status: {update_res.status_code} Body: {update_res.text}"
            )
            return False

    except Exception as e:
        logger.error(f"Tenant API Update Exception: {e}")
        return False
