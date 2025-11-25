import asyncio
import traceback
import structlog
import os
import time
import uuid
import requests
from pathlib import Path
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

import uvicorn
import redis.asyncio as async_redis
from api.core.config import settings
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi import status as http_status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .db.session import get_db, init_db
from .routers import (
    acapy_handler,
    cleanup,
    oidc,
    presentation_request,
    well_known_oid_config,
)
from .verificationConfigs.router import router as ver_configs_router
from .clientConfigurations.router import router as client_config_router
from .routers.socketio import sio_app, _build_redis_url, _handle_redis_failure
from api.core.oidc.provider import init_provider

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

# Setup loggers
logging_file_path = os.environ.get(
    "LOG_CONFIG_PATH", (Path(__file__).parent / "logging.conf").resolve()
)


os.environ["TZ"] = settings.TIMEZONE
time.tzset()


def get_application() -> FastAPI:
    application = FastAPI(
        title=settings.TITLE,
        description=settings.DESCRIPTION,
        debug=settings.DEBUG,
        # middleware=None,
    )
    return application


app = get_application()

# Serve static assets for the frontend
app.mount(
    "/static",
    StaticFiles(directory=(settings.CONTROLLER_TEMPLATE_DIR + "/assets")),
    name="static",
)

# Include routers
app.include_router(ver_configs_router, prefix="/ver_configs", tags=["ver_configs"])
app.include_router(client_config_router, prefix="/clients", tags=["oidc_clients"])
app.include_router(well_known_oid_config.router, tags=[".well-known"])
app.include_router(
    oidc.router, tags=["OpenID Connect Provider"], include_in_schema=False
)
app.include_router(acapy_handler.router, prefix="/webhooks", include_in_schema=False)
app.include_router(presentation_request.router, include_in_schema=False)
app.include_router(cleanup.router, tags=["cleanup"])

# DEPRECATED PATHS - For backwards compatibility with vc-authn-oidc 1.0
app.include_router(
    oidc.router, prefix="/vc/connect", tags=["oidc-deprecated"], include_in_schema=False
)

# Connect the websocket server to run within the FastAPI app
app.mount("/ws", sio_app)

origins = ["*"]

if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


async def _register_tenant_webhook(
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


@app.middleware("http")
async def logging_middleware(request: Request, call_next) -> Response:
    structlog.threadlocal.clear_threadlocal()
    structlog.threadlocal.bind_threadlocal(
        logger="uvicorn.access",
        request_id=str(uuid.uuid4()),
        cookies=request.cookies,
        scope=request.scope,
        url=str(request.url),
    )
    start_time = time.time()
    try:
        response: Response = await call_next(request)
        return response
    except Exception as e:
        process_time = time.time() - start_time
        logger.info(
            "failed to process a request",
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            process_time=process_time,
        )

        # Need to explicitly log the traceback
        logger.error(traceback.format_exc())

        return JSONResponse(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Internal Server Error",
                "process_time": process_time,
            },
        )
    else:
        process_time = time.time() - start_time
        logger.info(
            "processed a request",
            status_code=response.status_code,
            process_time=process_time,
        )


@app.on_event("startup")
async def on_tenant_startup():
    """Register any events we need to respond to."""
    await init_db()
    await init_provider(await get_db())

    # Check Redis availability if adapter is enabled
    if settings.USE_REDIS_ADAPTER:
        try:
            # Test Redis connectivity during startup
            redis_url = _build_redis_url()
            redis_client = async_redis.from_url(redis_url)
            await redis_client.ping()
            await redis_client.close()
            logger.info("Redis adapter is available and ready")
        except Exception as e:
            error_type = _handle_redis_failure("startup Redis check", e)
            logger.warning(
                f"Redis adapter enabled but unavailable (type: {error_type}) - continuing with degraded Socket.IO functionality"
            )
    else:
        logger.debug("Redis adapter disabled")

    # Robust Webhook Registration
    if settings.ACAPY_TENANCY == "multi":
        await _register_tenant_webhook(
            wallet_id=settings.MT_ACAPY_WALLET_ID,
            webhook_url=settings.CONTROLLER_WEB_HOOK_URL,
            admin_url=settings.ACAPY_ADMIN_URL,
            api_key=settings.CONTROLLER_API_KEY,
            admin_api_key=settings.ST_ACAPY_ADMIN_API_KEY,
            admin_api_key_name=settings.ST_ACAPY_ADMIN_API_KEY_NAME,
        )

    logger.info(">>> Starting up app new ...")


@app.on_event("shutdown")
async def on_tenant_shutdown():
    """Gracefully shutdown services."""
    logger.info(">>> Shutting down app ...")


@app.get("/", tags=["liveness", "readiness"])
@app.get("/health", tags=["liveness", "readiness"])
def main():
    return {"status": "ok", "health": "ok"}


if __name__ == "__main__":
    logger.info("main.")
    uvicorn.run(app, host="0.0.0.0", port=5100)
