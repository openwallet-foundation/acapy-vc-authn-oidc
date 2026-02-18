import json
import logging
import logging.config
import os
import re
import sys
from enum import Enum
from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import ConfigDict, field_validator

import structlog


# Removed in later versions of python
def strtobool(val: str | bool) -> bool:
    """Convert a string representation of truth to a boolean (True or False).
    True values are 'y', 'yes', 't', 'true', 'on', and '1'; False
    values are 'n', 'no', 'f', 'false', 'off', and '0'. If val is
    already a boolean it is simply returned.  Raises ValueError if
    'val' is anything else.
    """
    if isinstance(val, bool):
        return val

    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return True
    elif val in ("n", "no", "f", "false", "off", "0"):
        return False
    else:
        raise ValueError(f"invalid truth value {val}")


# Use environment variable to determine logging format
# default to True
# strtobool will convert the results of the environment variable to a bool
use_json_logs: bool = strtobool(
    os.environ.get("LOG_WITH_JSON", True)
    if os.environ.get("LOG_WITH_JSON", True) != ""
    else True
)

time_stamp_format: str = os.environ.get("LOG_TIMESTAMP_FORMAT", "iso")

with open((Path(__file__).parent.parent / "logconf.json").resolve()) as user_file:
    file_contents: dict = json.loads(user_file.read())
    logging.config.dictConfig(file_contents["logger"])


def determin_log_level():
    match os.environ.get("LOG_LEVEL"):
        case "DEBUG":
            return logging.DEBUG
        case "INFO":
            return logging.INFO
        case "WARNING":
            return logging.WARNING
        case "ERROR":
            return logging.ERROR
        case _:
            return logging.DEBUG


logging.basicConfig(
    format="%(message)s",
    stream=sys.stdout,
    level=determin_log_level(),
)

shared_processors = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_logger_name,
    structlog.stdlib.PositionalArgumentsFormatter(),
    structlog.stdlib.ExtraAdder(),
    structlog.processors.StackInfoRenderer(),
    structlog.stdlib.add_log_level,
    structlog.processors.TimeStamper(fmt=time_stamp_format),
]

renderer = (
    structlog.processors.JSONRenderer()
    if use_json_logs
    else structlog.dev.ConsoleRenderer()
)

# override uvicorn logging to use logstruct
formatter = structlog.stdlib.ProcessorFormatter(
    # These run ONLY on `logging` entries that do NOT originate within
    # structlog.
    foreign_pre_chain=shared_processors,
    # These run on ALL entries after the pre_chain is done.
    processors=[
        # Remove _record & _from_structlog.
        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
        renderer,
    ],
)

handler = logging.StreamHandler()
handler.setFormatter(formatter)

for _log in ["uvicorn", "uvicorn.error"]:
    # Clear the log handlers for uvicorn loggers, and enable propagation
    # so the messages are caught by our root logger and formatted correctly
    # by structlog
    logging.getLogger(_log).handlers.clear()
    logging.getLogger(_log).addHandler(handler)
    logging.getLogger(_log).propagate = False

# This is already handled by our middleware
logging.getLogger("uvicorn.access").handlers.clear()
logging.getLogger("uvicorn.access").propagate = False

# Configure structlog
structlog.configure(
    processors=[structlog.stdlib.filter_by_level] + shared_processors + [renderer],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.make_filtering_bound_logger(
        logging.getLogger().getEffectiveLevel()
    ),
    cache_logger_on_first_use=True,
)

# Setup logger for config
logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


class EnvironmentEnum(str, Enum):
    PRODUCTION = "production"
    LOCAL = "local"


def _get_redis_mode() -> str:
    """Determine Redis mode with backwards compatibility for USE_REDIS_ADAPTER.

    Priority:
    1. If REDIS_MODE env var is set, use it directly
    2. If legacy USE_REDIS_ADAPTER is set to true, return "single" with deprecation warning
    3. Default to "none" (Redis disabled)
    """
    mode = os.environ.get("REDIS_MODE")
    if mode:
        return mode.lower()

    # Legacy fallback for backwards compatibility
    use_adapter = os.environ.get("USE_REDIS_ADAPTER", "false")
    if strtobool(use_adapter):
        logger.warning(
            "USE_REDIS_ADAPTER is deprecated, use REDIS_MODE=single instead"
        )
        return "single"
    return "none"


class GlobalConfig(BaseSettings):
    TITLE: str = os.environ.get(
        "CONTROLLER_APP_TITLE", "acapy-vc-authn-oidc Controller"
    )
    DESCRIPTION: str = os.environ.get(
        "CONTROLLER_APP_DESCRIPTION",
        "An oidc authentication solution for verification credentials",
    )

    ENVIRONMENT: EnvironmentEnum
    DEBUG: bool = False
    TESTING: bool = False
    TIMEZONE: str = "UTC"

    # the following defaults match up with default values in scripts/.env.example
    # these MUST be all set in non-local environments.
    DB_HOST: str = os.environ.get("DB_HOST", "localhost")
    DB_PORT: int | str = os.environ.get("DB_PORT", "27017")
    DB_NAME: str = os.environ.get("DB_NAME", "oidc-controller")
    DB_USER: str = os.environ.get("OIDC_CONTROLLER_DB_USER", "oidccontrolleruser")
    DB_PASS: str = os.environ.get("OIDC_CONTROLLER_DB_USER_PWD", "oidccontrollerpass")

    MONGODB_URL: str = (
        f"""mongodb://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?retryWrites=true&w=majority"""  # noqa: E501
    )

    CONTROLLER_URL: str | None = os.environ.get("CONTROLLER_URL")
    CONTROLLER_WEB_HOOK_URL: str | None = os.environ.get("CONTROLLER_WEB_HOOK_URL")
    # Where to send users when trying to scan with their mobile camera (not a wallet)
    CONTROLLER_CAMERA_REDIRECT_URL: str | None = os.environ.get(
        "CONTROLLER_CAMERA_REDIRECT_URL"
    )
    # The number of seconds to wait for a presentation to be verified, Default: 10
    CONTROLLER_PRESENTATION_EXPIRE_TIME: int = os.environ.get(
        "CONTROLLER_PRESENTATION_EXPIRE_TIME", 10
    )

    # How long auth_sessions with matching the states in
    # CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE are stored for in seconds
    CONTROLLER_PRESENTATION_CLEANUP_TIME: int = os.environ.get(
        "CONTROLLER_PRESENTATION_CLEANUP_TIME", 86400
    )

    # Presentation record cleanup configuration
    # How long to retain presentation records in hours (default: 24 hours)
    CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS: int = int(
        os.environ.get("CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS", 24)
    )

    # Resource limits for cleanup operations to prevent excessive processing
    # Maximum presentation records to process per cleanup cycle (default: 1000)
    CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS: int = int(
        os.environ.get("CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS", 1000)
    )
    # Maximum connections to process per cleanup cycle (default: 2000)
    CONTROLLER_CLEANUP_MAX_CONNECTIONS: int = int(
        os.environ.get("CONTROLLER_CLEANUP_MAX_CONNECTIONS", 2000)
    )

    CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE: str | None = os.environ.get(
        "CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE"
    )

    # Feature Flags
    # Enable OIDC UserInfo endpoint (Ephemeral/Compatibility Mode). Defaults to False.
    CONTROLLER_ENABLE_USERINFO_ENDPOINT: bool = strtobool(
        os.environ.get("CONTROLLER_ENABLE_USERINFO_ENDPOINT", False)
    )

    ACAPY_AGENT_URL: str | None = os.environ.get("ACAPY_AGENT_URL")
    if not ACAPY_AGENT_URL:
        logger.warning("ACAPY_AGENT_URL was not provided, agent will not be accessible")

    # valid options are "multi", "single", and "traction"
    ACAPY_TENANCY: str = os.environ.get("ACAPY_TENANCY", "single")

    ACAPY_ADMIN_URL: str = os.environ.get("ACAPY_ADMIN_URL", "http://localhost:8031")

    ACAPY_PROOF_FORMAT: str = os.environ.get("ACAPY_PROOF_FORMAT", "indy")

    # Unified Tenant Configuration with Legacy Fallback
    # 1. Try unified variable
    # 2. Fallback to legacy MT_ variable
    # 3. Default to None
    ACAPY_TENANT_WALLET_ID: str | None = os.environ.get(
        "ACAPY_TENANT_WALLET_ID", os.environ.get("MT_ACAPY_WALLET_ID")
    )

    ACAPY_TENANT_WALLET_KEY: str | None = os.environ.get(
        "ACAPY_TENANT_WALLET_KEY", os.environ.get("MT_ACAPY_WALLET_KEY", "random-key")
    )

    # Token Cache Configuration (seconds) - Default 1 hour
    ACAPY_TOKEN_CACHE_TTL: int = int(os.environ.get("ACAPY_TOKEN_CACHE_TTL", 3600))

    ST_ACAPY_ADMIN_API_KEY_NAME: str | None = os.environ.get(
        "ST_ACAPY_ADMIN_API_KEY_NAME"
    )
    ST_ACAPY_ADMIN_API_KEY: str | None = os.environ.get("ST_ACAPY_ADMIN_API_KEY")
    DB_ECHO_LOG: bool = False

    DEFAULT_PAGE_SIZE: int | str = os.environ.get("DEFAULT_PAGE_SIZE", 10)

    # openssl rand -hex 32
    SIGNING_KEY_SIZE: int = os.environ.get("SIGNING_KEY_SIZE", 2048)
    # SIGNING_KEY_FILEPATH expects complete path including filename and extension.
    SIGNING_KEY_FILEPATH: str | None = os.environ.get("SIGNING_KEY_FILEPATH")
    SIGNING_KEY_ALGORITHM: str = os.environ.get("SIGNING_KEY_ALGORITHM", "RS256")
    SUBJECT_ID_HASH_SALT: str = os.environ.get("SUBJECT_ID_HASH_SALT", "test_hash_salt")

    # OIDC Client Settings
    # Duration in seconds for Access Tokens (Default: 1 hour)
    OIDC_ACCESS_TOKEN_TTL: int = int(os.environ.get("OIDC_ACCESS_TOKEN_TTL", 3600))

    @field_validator("OIDC_ACCESS_TOKEN_TTL")
    @classmethod
    def validate_token_ttl(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("OIDC_ACCESS_TOKEN_TTL must be a positive integer")
        return v

    OIDC_CLIENT_ID: str = os.environ.get("OIDC_CLIENT_ID", "keycloak")
    OIDC_CLIENT_NAME: str = os.environ.get("OIDC_CLIENT_NAME", "keycloak")
    OIDC_CLIENT_REDIRECT_URI: str = os.environ.get(
        "OIDC_CLIENT_REDIRECT_URI",
        "http://localhost:8880/auth/realms/vc-authn/broker/vc-authn/endpoint",
    )
    OIDC_CLIENT_SECRET: str = os.environ.get("OIDC_CLIENT_SECRET", "**********")

    # OIDC Controller Settings
    INVITATION_LABEL: str = os.environ.get("INVITATION_LABEL", "VC-AuthN")
    CONTROLLER_API_KEY: str = os.environ.get("CONTROLLER_API_KEY", "")
    USE_OOB_LOCAL_DID_SERVICE: bool = strtobool(
        os.environ.get("USE_OOB_LOCAL_DID_SERVICE", True)
    )
    USE_CONNECTION_BASED_VERIFICATION: bool = strtobool(
        os.environ.get("USE_CONNECTION_BASED_VERIFICATION", True)
    )
    WALLET_DEEP_LINK_PREFIX: str = os.environ.get(
        "WALLET_DEEP_LINK_PREFIX", "bcwallet://aries_proof-request"
    )
    SET_NON_REVOKED: bool = strtobool(os.environ.get("SET_NON_REVOKED", True))

    CONTROLLER_VARIABLE_SUBSTITUTION_OVERRIDE: str | None = os.environ.get(
        "CONTROLLER_VARIABLE_SUBSTITUTION_OVERRIDE"
    )
    CONTROLLER_TEMPLATE_DIR: str = os.environ.get(
        "CONTROLLER_TEMPLATE_DIR", "/app/controller-config/templates"
    )

    # Redis Configuration for multi-pod Socket.IO
    # REDIS_MODE: "none", "single", "sentinel", or "cluster"
    # - none: Redis disabled (default for backwards compatibility)
    # - single: Single Redis instance (REDIS_HOST = "host:port")
    # - sentinel: Redis Sentinel (REDIS_HOST = "host1:port1,host2:port2")
    # - cluster: Redis Cluster (REDIS_HOST = "host1:port1,host2:port2")
    # REDIS_HOST is always comma-separated host:port pairs.
    # For single mode, only one entry is allowed.
    REDIS_MODE: str = _get_redis_mode()
    REDIS_HOST: str = os.environ.get("REDIS_HOST", "redis")
    # REDIS_PORT is deprecated — embed the port in REDIS_HOST (e.g., "redis:6379").
    # Kept only as fallback when REDIS_HOST has no port in single mode.
    REDIS_PORT: int = int(os.environ.get("REDIS_PORT", 6379))
    REDIS_PASSWORD: str | None = os.environ.get("REDIS_PASSWORD")
    REDIS_DB: int = int(os.environ.get("REDIS_DB", 0))

    # Sentinel-specific configuration (only used when REDIS_MODE=sentinel)
    REDIS_SENTINEL_MASTER_NAME: str = os.environ.get(
        "REDIS_SENTINEL_MASTER_NAME", "mymaster"
    )

    @property
    def USE_REDIS_ADAPTER(self) -> bool:
        """Backwards compatibility property - derived from REDIS_MODE."""
        return self.REDIS_MODE.lower() != "none"

    # Redis error handling and retry configuration
    REDIS_THREAD_MAX_RETRIES: int = int(os.environ.get("REDIS_THREAD_MAX_RETRIES", 5))
    REDIS_PUBSUB_MAX_FAILURES: int = int(
        os.environ.get("REDIS_PUBSUB_MAX_FAILURES", 10)
    )
    REDIS_RETRY_BASE_DELAY: int = int(os.environ.get("REDIS_RETRY_BASE_DELAY", 1))
    REDIS_RETRY_MAX_DELAY: int = int(os.environ.get("REDIS_RETRY_MAX_DELAY", 60))

    model_config = ConfigDict(case_sensitive=True)


class LocalConfig(GlobalConfig):
    """Local configurations."""

    DEBUG: bool = True
    DB_ECHO_LOG: bool = True
    ENVIRONMENT: EnvironmentEnum = EnvironmentEnum.LOCAL


class ProdConfig(GlobalConfig):
    """Production configurations."""

    DEBUG: bool = False
    ENVIRONMENT: EnvironmentEnum = EnvironmentEnum.PRODUCTION


class FactoryConfig:
    def __init__(self, environment: str | None):
        self.environment = environment

    def __call__(self) -> GlobalConfig:
        if self.environment == EnvironmentEnum.LOCAL.value:
            return LocalConfig()
        return ProdConfig()


@lru_cache()
def get_configuration() -> GlobalConfig:
    return FactoryConfig(os.environ.get("ENVIRONMENT"))()


settings = get_configuration()

# Startup validation for ACAPY_PROOF_FORMAT
if settings.ACAPY_PROOF_FORMAT not in ["indy", "anoncreds"]:
    raise ValueError(
        f"ACAPY_PROOF_FORMAT must be 'indy' or 'anoncreds', got '{settings.ACAPY_PROOF_FORMAT}'"
    )

# Startup validation for CONTROLLER_WEB_HOOK_URL in Multi-Tenant mode
if (
    settings.ACAPY_TENANCY in ["multi", "traction"]
    and not settings.CONTROLLER_WEB_HOOK_URL
):
    logger.warning(
        f"ACAPY_TENANCY is set to '{settings.ACAPY_TENANCY}' but CONTROLLER_WEB_HOOK_URL is missing. "
        "The controller will not be able to register webhooks with the tenant wallet, "
        "which may cause verification flows to hang."
    )

# Startup validation for ACAPY_TOKEN_CACHE_TTL
if settings.ACAPY_TOKEN_CACHE_TTL <= 0:
    raise ValueError(
        f"ACAPY_TOKEN_CACHE_TTL must be a positive integer, got '{settings.ACAPY_TOKEN_CACHE_TTL}'"
    )


def normalize_redis_config():
    """Apply backwards-compatibility transformations to Redis settings.

    If REDIS_MODE=single and REDIS_HOST is a bare hostname with no port,
    REDIS_PORT is appended automatically with a deprecation warning.

    This mutates the settings singleton and must be called exactly once,
    before validate_redis_config(), during application startup.
    """
    if settings.REDIS_MODE.lower() != "single":
        return
    if ":" not in settings.REDIS_HOST:
        logger.warning(
            "REDIS_HOST without a port is deprecated. "
            f"Use REDIS_HOST={settings.REDIS_HOST}:{settings.REDIS_PORT} instead. "
            "REDIS_PORT will be removed in a future release."
        )
        settings.REDIS_HOST = f"{settings.REDIS_HOST}:{settings.REDIS_PORT}"


def validate_redis_config():
    """Validate Redis configuration. Pure — no side effects.

    REDIS_HOST must be comma-separated host:port pairs for all non-none modes.
    For single mode, exactly one entry is required.

    Call normalize_redis_config() before this if backwards-compat normalization
    is needed (i.e., at application startup).

    Raises ValueError with a clear message if configuration is invalid.
    """
    mode = settings.REDIS_MODE.lower()

    if mode == "none":
        return

    if mode not in ("single", "sentinel", "cluster"):
        raise ValueError(
            f"Invalid REDIS_MODE: '{mode}'. Must be one of: none, single, sentinel, cluster"
        )

    host_port_pattern = re.compile(r"^[\w.\-]+:\d+$")
    nodes = [n.strip() for n in settings.REDIS_HOST.split(",") if n.strip()]

    if not nodes:
        raise ValueError(
            f"REDIS_MODE={mode} requires at least one node in REDIS_HOST."
        )

    for node in nodes:
        if not host_port_pattern.match(node):
            raise ValueError(
                f"REDIS_MODE={mode} requires REDIS_HOST as host:port pairs. "
                f"Invalid node: '{node}'. "
                f"Expected format: 'host:port' (e.g., 'redis:6379' or 'sentinel1:26379,sentinel2:26379')"
            )

    if mode == "single" and len(nodes) > 1:
        raise ValueError(
            f"REDIS_MODE=single but REDIS_HOST contains multiple hosts: '{settings.REDIS_HOST}'. "
            f"For single mode, use one host:port (e.g., REDIS_HOST=redis:6379). "
            f"For multiple nodes, use REDIS_MODE=sentinel or REDIS_MODE=cluster."
        )


# Normalize at import time so any module that imports settings (e.g. socketio.py
# calling validate_redis_config() at module load) sees host:port format already.
normalize_redis_config()
