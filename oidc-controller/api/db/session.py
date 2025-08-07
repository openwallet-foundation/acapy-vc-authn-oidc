import json
import structlog
from pymongo import MongoClient, ASCENDING
from pymongo.collection import Collection
from pymongo.errors import OperationFailure
from pathlib import Path
from api.core.config import settings
from .collections import COLLECTION_NAMES
from ..authSessions.models import AuthSessionState


async def get_async_session():
    yield None


client = MongoClient(settings.MONGODB_URL, uuidRepresentation="standard")
logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


def apply_expiration_times(auth_session: Collection, expiration_times: list[str]):
    # Create all indexes based on the config file
    index_name = "auth_session_ttl"

    try:
        auth_session.create_index(
            [("created_at", ASCENDING)],
            expireAfterSeconds=settings.CONTROLLER_PRESENTATION_CLEANUP_TIME,
            name=index_name,
            partialFilterExpression={
                "$or": [{"proof_status": {"$eq": state}} for state in expiration_times]
            },
        )
    except OperationFailure:
        # Warn the user if the index already exists
        logger.warning(
            "The index "
            + index_name
            + " already exists. It must manually be deleted to "
            + "update the timeout or matched AuthSessionState's"
        )


def create_ttl_indexes(auth_session: Collection, file: str):
    auth_session_states: list[str] = [str(i) for i in list(AuthSessionState)]
    try:
        with open(Path(file).resolve()) as user_file:
            expiration_times: list[str] = json.load(user_file)
            # Ensure the given config is valid
            if not all(
                isinstance(status, str) and (status in auth_session_states)
                for status in expiration_times
            ):
                raise Exception("Invalid json formatting")

    except Exception as e:
        match e:
            case FileNotFoundError():
                logger.warning(
                    "The file "
                    + file
                    + " does not exist or could not be opened "
                    + "because of this no auth session timeouts will be applied.",
                )
            case json.JSONDecodeError():
                logger.warning(
                    "Failed to decode the auth session timeouts timeout config file "
                    + file
                    + " with the following error "
                    + str(e),
                )
            case Exception():
                logger.error(
                    "There is at least one invalid entry in the file "
                    + file
                    + ". The timeout config file should contain "
                    + "a JSON array of AuthSessionStates."
                    + "valid auth session strings are "
                    + str(auth_session_states)
                    + ". No expiration times will be applied",
                )
    else:
        apply_expiration_times(auth_session, expiration_times)


async def init_db():
    # must be idempotent
    db = client[settings.DB_NAME]
    ver_configs = db.get_collection(COLLECTION_NAMES.VER_CONFIGS)
    ver_configs.create_index([("ver_config_id", ASCENDING)], unique=True)

    client_configs = db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS)
    client_configs.create_index([("client_id", ASCENDING)], unique=True)

    auth_session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
    auth_session.create_index([("pres_exch_id", ASCENDING)], unique=True)
    auth_session.create_index([("pyop_auth_code", ASCENDING)], unique=True)
    # Sparse unique index for socket_id - allows multiple null values but ensures uniqueness for non-null values
    auth_session.create_index([("socket_id", ASCENDING)], unique=True, sparse=True)
    if settings.CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE:
        create_ttl_indexes(
            auth_session, settings.CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE
        )
    else:
        logger.warn(
            "No configuration file was set for CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE"
            + " No expiration times will be applied.",
        )


async def get_db():
    return client[settings.DB_NAME]
