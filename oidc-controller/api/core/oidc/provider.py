import os
import secrets
import json
from urllib.parse import urlparse
from datetime import datetime, timedelta

import structlog
import structlog.typing
import redis
from api.clientConfigurations.models import TOKENENDPOINTAUTHMETHODS
from api.core.config import settings
from api.core.models import VCUserinfo
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwkest.jwk import KEYS, RSAKey, rsa_load
from pymongo.database import Database
from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.storage import RedisWrapper, StatelessWrapper
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory

logger: structlog.typing.FilteringBoundLogger = structlog.get_logger()
DIR_PATH = os.path.dirname(os.path.realpath(__file__))


def get_signing_key_dir_path(to_replace_str, replacement_str, filename_str) -> str:
    """Get signing key directory."""
    file_path = DIR_PATH.replace(to_replace_str, replacement_str)
    if not os.path.exists(file_path):
        os.makedirs(file_path)
    return os.path.join(file_path, filename_str)


def save_pem_file(filename, content):
    """Save the pem file in oidc-controller dir."""
    f = open(filename, "wb")
    f.write(content)
    f.close()


def pem_file_exists(filepath) -> bool:
    """Check if pem file exists."""
    return os.path.isfile(filepath)


def _build_redis_url():
    """Build Redis connection URL from settings"""
    if settings.REDIS_PASSWORD:
        return f"redis://:{settings.REDIS_PASSWORD}@{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
    else:
        return (
            f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
        )


class RedisWrapperWithPack(RedisWrapper):
    """
    Wrapper around PyOP's RedisWrapper that implements pack() and unpack() methods.

    PyOP's RedisWrapper doesn't implement these methods (raises NotImplementedError),
    but the application code calls .pack() to regenerate authorization codes.

    This wrapper stores values in Redis (shared across pods) and returns a random key.
    Unlike StatelessWrapper which encrypts data into the token, this approach uses
    Redis as a shared data store accessible by all pods.
    """

    def pack(self, value):
        """
        Generate a random key, store the value in Redis, and return the key.

        This enables multi-pod deployments - the value is stored in Redis
        where all pods can access it.
        """
        key = secrets.token_urlsafe(32)
        self[key] = value
        logger.debug(
            "Stored value in Redis",
            operation="pack",
            collection=self.collection,
            key_prefix=key[:8],
            ttl=self.ttl,
        )
        return key

    def unpack(self, key):
        """
        Retrieve and return the value for the given key from Redis.

        Raises KeyError if the key doesn't exist in Redis.
        """
        try:
            value = self[key]
            logger.debug(
                "Retrieved value from Redis",
                operation="unpack",
                collection=self.collection,
                key_prefix=key[:8],
            )
            return value
        except KeyError:
            logger.warning(
                "Key not found in Redis",
                operation="unpack",
                collection=self.collection,
                key_prefix=key[:8],
            )
            raise


if settings.TESTING:
    # Test pem file location /vc-authn-oidc/test-signing-keys.
    SIGNING_KEY_FILEPATH = get_signing_key_dir_path(
        to_replace_str="/oidc-controller/api/core/oidc",
        replacement_str="/test-signing-keys",
        filename_str="test_signing_key.pem",
    )
else:
    if not settings.SIGNING_KEY_FILEPATH:
        # Default pem file location /app/signing-keys.
        SIGNING_KEY_FILEPATH = get_signing_key_dir_path(
            to_replace_str="/api/core/oidc",
            replacement_str="/signing-keys",
            filename_str="signing_key.pem",
        )
    else:
        SIGNING_KEY_FILEPATH = settings.SIGNING_KEY_FILEPATH
        logger.info(
            f"SIGNING_KEY_FILEPATH {SIGNING_KEY_FILEPATH} env variable provided."
        )

if not pem_file_exists(SIGNING_KEY_FILEPATH):
    logger.info("creating new pem file")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(settings.SIGNING_KEY_SIZE),
        backend=default_backend(),
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    save_pem_file(SIGNING_KEY_FILEPATH, pem)
else:
    logger.info("pem file alrady exists")
logger.info(f"pem file located at {SIGNING_KEY_FILEPATH}.")

issuer_url = settings.CONTROLLER_URL
if urlparse(issuer_url).scheme != "https":
    logger.error("CONTROLLER_URL is not HTTPS. changing openid-config for development")
    issuer_url = issuer_url[:4] + "s" + issuer_url[4:]
signing_key = RSAKey(
    key=rsa_load(SIGNING_KEY_FILEPATH), use="sig", alg=settings.SIGNING_KEY_ALGORITHM
)
signing_keys = KEYS().append(signing_key)


class DynamicClientDatabase(dict):
    """
    Dynamic client database that loads clients from MongoDB on-demand.

    This ensures all controller pods see the same client configurations
    without requiring provider reloads when clients are added/updated.
    """

    def __init__(self, db_getter):
        """
        Initialize with a callable that returns a MongoDB Database.

        Args:
            db_getter: Callable that returns pymongo.database.Database
        """
        super().__init__()
        self._db_getter = db_getter
        self._cache = {}
        self._cache_time = {}
        self._cache_ttl = 60  # Cache clients for 60 seconds

    def _get_client_from_db(self, client_id: str):
        """Load client from MongoDB."""
        from api.db.session import COLLECTION_NAMES
        import time

        # Check cache first
        if client_id in self._cache:
            if time.time() - self._cache_time[client_id] < self._cache_ttl:
                logger.debug(
                    "Client loaded from cache",
                    client_id=client_id,
                    source="cache",
                    cache_age=time.time() - self._cache_time[client_id],
                )
                return self._cache[client_id]

        # Load from database
        logger.debug(
            "Loading client from MongoDB", client_id=client_id, source="mongodb"
        )
        db = self._db_getter()
        col = db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS)
        client_doc = col.find_one({"client_id": client_id})

        if client_doc:
            # Remove MongoDB _id field
            client_doc.pop("_id", None)
            # Cache the result
            self._cache[client_id] = client_doc
            self._cache_time[client_id] = time.time()
            logger.debug(
                "Client loaded from MongoDB and cached",
                client_id=client_id,
                source="mongodb",
                cached=True,
            )
            return client_doc

        logger.warning(
            "Client not found in MongoDB", client_id=client_id, source="mongodb"
        )
        return None

    def __getitem__(self, key):
        client = self._get_client_from_db(key)
        if client is None:
            raise KeyError(f"client_id '{key}' unknown")
        return client

    def __contains__(self, key):
        return self._get_client_from_db(key) is not None

    def get(self, key, default=None):
        client = self._get_client_from_db(key)
        return client if client is not None else default

    def keys(self):
        """Return all client IDs from database."""
        from api.db.session import COLLECTION_NAMES

        db = self._db_getter()
        col = db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS)
        return [doc["client_id"] for doc in col.find({}, {"client_id": 1})]

    def values(self):
        """Return all clients from database."""
        for client_id in self.keys():
            yield self[client_id]

    def items(self):
        """Return all (client_id, client) pairs from database."""
        for client_id in self.keys():
            yield client_id, self[client_id]


# Define constants so that they can be imported for route definition in routers/oidc.py
AuthorizeUriEndpoint = "authorize"
TokenUriEndpoint = "token"

# TODO validate the correctness of this? either change config or add capabilities
configuration_information = {
    "issuer": issuer_url,
    "authorization_endpoint": f"{issuer_url}/{AuthorizeUriEndpoint}",
    "token_endpoint": f"{issuer_url}/{TokenUriEndpoint}",
    "jwks_uri": f"{issuer_url}/.well-known/openid-configuration/jwks",
    "response_types_supported": ["code", "id_token", "token"],
    "id_token_signing_alg_values_supported": [signing_key.alg],
    "response_modes_supported": ["fragment", "query", "form_post"],
    "subject_types_supported": ["public"],
    "grant_types_supported": ["hybrid"],
    "claim_types_supported": ["normal"],
    "claims_parameter_supported": False,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": False,
    "scopes_supported": ["openid"],
    "token_endpoint_auth_methods_supported": TOKENENDPOINTAUTHMETHODS.list(),
    "frontchannel_logout_supported": True,
    "frontchannel_logout_session_supported": True,
    "backchannel_logout_supported": True,
    "backchannel_logout_session_supported": True,
}

subject_id_factory = HashBasedSubjectIdentifierFactory(settings.SUBJECT_ID_HASH_SALT)

# Conditionally create storage backends based on USE_REDIS_ADAPTER setting
if settings.USE_REDIS_ADAPTER:
    # Redis storage for multi-pod deployments - shared state across all pods
    redis_url = _build_redis_url()

    authorization_code_storage = RedisWrapperWithPack(
        db_uri=redis_url,
        collection="pyop_authorization_codes",
        ttl=600,  # 10 minutes
    )

    access_token_storage = RedisWrapperWithPack(
        db_uri=redis_url,
        collection="pyop_access_tokens",
        ttl=3600,  # 1 hour
    )

    refresh_token_storage = RedisWrapperWithPack(
        db_uri=redis_url,
        collection="pyop_refresh_tokens",
        ttl=2592000,  # 30 days
    )

    subject_identifier_storage = RedisWrapperWithPack(
        db_uri=redis_url,
        collection="pyop_subject_identifiers",
        ttl=None,  # No expiration
    )

    logger.info(
        "Initialized Redis storage for PyOP tokens",
        storage_backend="redis",
        redis_host=settings.REDIS_HOST,
        redis_port=settings.REDIS_PORT,
        multi_pod_enabled=True,
    )
else:
    # StatelessWrapper for single-pod deployments - tokens are self-contained
    stateless_storage = StatelessWrapper("vc-authn", secrets.token_urlsafe())

    authorization_code_storage = stateless_storage
    access_token_storage = stateless_storage
    refresh_token_storage = stateless_storage
    subject_identifier_storage = stateless_storage

    logger.info(
        "Initialized StatelessWrapper storage for PyOP tokens",
        storage_backend="stateless",
        multi_pod_enabled=False,
        warning="Multi-pod deployments will NOT work with StatelessWrapper",
    )

# placeholder that gets set on app_start and write operations to ClientConfigurationCRUD
provider = None


async def init_provider(db: Database):
    """
    Initialize the PyOP provider instance.

    Uses DynamicClientDatabase to ensure all pods see the same client configurations
    without requiring provider reloads when clients are added/updated.
    """
    global provider
    from api.db.session import client as mongo_client

    # Create a callable that returns the database
    def get_db():
        return mongo_client[settings.DB_NAME]

    # Use dynamic client database that loads from MongoDB on-demand
    client_db = DynamicClientDatabase(get_db)

    provider = Provider(
        signing_key,
        configuration_information,
        AuthorizationState(
            subject_id_factory,
            authorization_code_db=authorization_code_storage,
            access_token_db=access_token_storage,
            refresh_token_db=refresh_token_storage,
            subject_identifier_db=subject_identifier_storage,
        ),
        client_db,
        VCUserinfo({}),
    )
