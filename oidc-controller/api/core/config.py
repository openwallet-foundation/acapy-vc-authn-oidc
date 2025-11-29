import json
import logging
import logging.config
import os
import sys
from enum import Enum
from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Any

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
    ACAPY_AGENT_URL: str | None = os.environ.get("ACAPY_AGENT_URL")
    if not ACAPY_AGENT_URL:
        logger.warning("ACAPY_AGENT_URL was not provided, agent will not be accessible")

    # valid options are "multi", "single", and "traction"
    ACAPY_TENANCY: str = os.environ.get("ACAPY_TENANCY", "single")

    ACAPY_ADMIN_URL: str = os.environ.get("ACAPY_ADMIN_URL", "http://localhost:8031")

    ACAPY_PROOF_FORMAT: str = os.environ.get("ACAPY_PROOF_FORMAT", "indy")

    MT_ACAPY_WALLET_ID: str | None = os.environ.get("MT_ACAPY_WALLET_ID")
    MT_ACAPY_WALLET_KEY: str = os.environ.get("MT_ACAPY_WALLET_KEY", "random-key")

    # Traction Configuration
    TRACTION_TENANT_ID: str | None = os.environ.get("TRACTION_TENANT_ID")
    TRACTION_TENANT_API_KEY: str | None = os.environ.get("TRACTION_TENANT_API_KEY")

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
    REDIS_HOST: str = os.environ.get("REDIS_HOST", "redis")
    REDIS_PORT: int = int(os.environ.get("REDIS_PORT", 6379))
    REDIS_PASSWORD: str | None = os.environ.get("REDIS_PASSWORD")
    REDIS_DB: int = int(os.environ.get("REDIS_DB", 0))
    USE_REDIS_ADAPTER: bool = strtobool(os.environ.get("USE_REDIS_ADAPTER", False))

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
