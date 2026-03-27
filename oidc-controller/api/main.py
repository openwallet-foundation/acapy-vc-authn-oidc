import os
import time
import traceback
import uuid
from pathlib import Path

import httpx
import structlog
import uvicorn
from fastapi import FastAPI
from fastapi import status as http_status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request
from starlette.responses import Response

from api.core.acapy.config import MultiTenantAcapy, TractionTenantAcapy
from api.core.config import settings, validate_redis_config
from api.core.oidc.provider import init_provider
from api.core.webhook_utils import register_tenant_webhook

from .clientConfigurations.router import router as client_config_router
from .core.redis_utils import (
    _handle_redis_failure,
    build_redis_url,
    can_we_reach_cluster,
    can_we_reach_redis,
    can_we_reach_sentinel,
    parse_host_port_pairs,
)
from .db.session import get_db, init_db
from .routers import (
    acapy_handler,
    cleanup,
    oidc,
    presentation_request,
    well_known_oid_config,
)
from .routers.sse import (
    build_async_redis_client,
    set_redis_client,
)
from .routers.sse import (
    router as sse_router,
)
from .verificationConfigs.router import router as ver_configs_router

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
app.include_router(sse_router, include_in_schema=False)

# DEPRECATED PATHS - For backwards compatibility with vc-authn-oidc 1.0
app.include_router(
    oidc.router, prefix="/vc/connect", tags=["oidc-deprecated"], include_in_schema=False
)

origins = ["*"]

if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
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
    except Exception:
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
    # Mount static assets here (not at module level) so the directory is
    # validated at startup time rather than at import time, which allows
    # CONTROLLER_TEMPLATE_DIR to be set via fixtures in tests.
    app.mount(
        "/static",
        StaticFiles(directory=(settings.CONTROLLER_TEMPLATE_DIR + "/assets")),
        name="static",
    )

    app.state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.ACAPY_REQUEST_TIMEOUT),
        limits=httpx.Limits(
            max_keepalive_connections=20,
            max_connections=100,
            keepalive_expiry=30,
        ),
    )

    validate_redis_config()

    await init_db()
    await init_provider(await get_db())

    # Check Redis availability if enabled.
    # Redis is required for both SSE cross-pod messaging AND PyOP token
    # storage — if it's unreachable the entire auth flow is broken, so we fail
    # fast here rather than starting and crashing on every request.
    mode = settings.REDIS_MODE.lower()
    if mode == "none":
        logger.debug("Redis disabled (REDIS_MODE=none)")
    else:
        try:
            reachable = False
            if mode == "single":
                reachable = can_we_reach_redis(build_redis_url())
            elif mode == "sentinel":
                hosts = parse_host_port_pairs(settings.REDIS_HOST)
                reachable = can_we_reach_sentinel(
                    hosts, settings.REDIS_SENTINEL_MASTER_NAME
                )
            elif mode == "cluster":
                hosts = parse_host_port_pairs(settings.REDIS_HOST)
                reachable = can_we_reach_cluster(hosts)

            if reachable:
                logger.info(f"Redis is available and ready (mode={mode})")
                # Initialize async Redis client for SSE pub/sub
                redis_client = await build_async_redis_client()
                app.state.redis_client = redis_client
                set_redis_client(redis_client)
                logger.info(f"SSE Redis pub/sub client initialized (mode={mode})")
            else:
                raise RuntimeError(
                    f"REDIS_MODE={mode} is configured but Redis is not reachable "
                    f"(REDIS_HOST={settings.REDIS_HOST}). "
                    "Ensure Redis is running and accessible, "
                    "or set REDIS_MODE=none to disable Redis."
                )
        except RuntimeError:
            raise
        except Exception as e:
            error_type = _handle_redis_failure("startup Redis check", e)
            raise RuntimeError(
                f"Redis startup check failed (REDIS_MODE={mode}, "
                f"REDIS_HOST={settings.REDIS_HOST}, error_type={error_type}): {e}"
            ) from e

    # Robust Webhook Registration
    if settings.ACAPY_TENANCY == "multi":
        logger.debug(
            "Starting up in Multi-Tenant Admin Mode",
            mode="multi",
            expected_id="Wallet ID (ACAPY_TENANT_WALLET_ID or MT_ACAPY_WALLET_ID)",
            expected_key="Wallet Key (ACAPY_TENANT_WALLET_KEY or MT_ACAPY_WALLET_KEY)",
            webhook_registration="Admin API (/multitenancy/wallet/{id})",
        )

        token_fetcher = None
        if settings.ACAPY_TENANT_WALLET_KEY:
            token_fetcher = MultiTenantAcapy(app.state.http_client).get_wallet_token

        await register_tenant_webhook(
            wallet_id=settings.ACAPY_TENANT_WALLET_ID,
            webhook_url=settings.CONTROLLER_WEB_HOOK_URL,
            admin_url=settings.ACAPY_ADMIN_URL,
            api_key=settings.CONTROLLER_API_KEY,
            admin_api_key=settings.ST_ACAPY_ADMIN_API_KEY,
            admin_api_key_name=settings.ST_ACAPY_ADMIN_API_KEY_NAME,
            http_client=app.state.http_client,
            token_fetcher=token_fetcher,
            use_admin_api=True,
        )

    elif settings.ACAPY_TENANCY == "traction":
        logger.debug(
            "Starting up in Traction Mode",
            mode="traction",
            expected_id="Traction Tenant ID (ACAPY_TENANT_WALLET_ID)",
            expected_key="Traction Tenant API Key (ACAPY_TENANT_WALLET_KEY)",
            webhook_registration="Tenant API (/tenant/wallet)",
        )

        token_fetcher = TractionTenantAcapy(app.state.http_client).get_wallet_token

        await register_tenant_webhook(
            wallet_id=settings.ACAPY_TENANT_WALLET_ID,  # Optional/Unused for traction mode registration
            webhook_url=settings.CONTROLLER_WEB_HOOK_URL,
            admin_url=settings.ACAPY_ADMIN_URL,
            api_key=settings.CONTROLLER_API_KEY,
            admin_api_key=None,  # Not used in direct tenant update
            admin_api_key_name=None,
            http_client=app.state.http_client,
            token_fetcher=token_fetcher,
            use_admin_api=False,
        )

    logger.info(">>> Starting up app new ...")


@app.on_event("shutdown")
async def on_tenant_shutdown():
    """Gracefully shutdown services."""
    logger.info(">>> Shutting down app ...")
    if hasattr(app.state, "http_client"):
        await app.state.http_client.aclose()
    if hasattr(app.state, "redis_client"):
        await app.state.redis_client.aclose()


@app.get("/", tags=["liveness", "readiness"])
@app.get("/health", tags=["liveness", "readiness"])
def main():
    return {"status": "ok", "health": "ok"}


if __name__ == "__main__":
    logger.info("main.")
    uvicorn.run(app, host="0.0.0.0", port=5100)
