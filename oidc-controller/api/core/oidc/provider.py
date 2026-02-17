import json
import os
import secrets
from urllib.parse import urlparse

import redis
import structlog
import structlog.typing
from api.clientConfigurations.models import TOKENENDPOINTAUTHMETHODS
from api.core.config import settings
from api.core.models import VCUserinfo
from api.core.redis_utils import parse_host_port_pairs, build_redis_url
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwkest.jwk import KEYS, RSAKey, rsa_load
from pymongo.database import Database
from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.storage import StatelessWrapper
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from redis.sentinel import Sentinel

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




def _get_sentinel_master():
    """Get a Redis master connection via Sentinel."""
    sentinel_hosts = parse_host_port_pairs(settings.REDIS_HOST)

    sentinel_kwargs = {}
    if settings.REDIS_PASSWORD:
        sentinel_kwargs["password"] = settings.REDIS_PASSWORD

    sentinel = Sentinel(sentinel_hosts, sentinel_kwargs=sentinel_kwargs)
    return sentinel.master_for(
        settings.REDIS_SENTINEL_MASTER_NAME, password=settings.REDIS_PASSWORD
    )


def _get_cluster_client():
    """Get a Redis Cluster client."""
    from redis.cluster import RedisCluster, ClusterNode

    hosts = parse_host_port_pairs(settings.REDIS_HOST)
    startup_nodes = [ClusterNode(host, port) for host, port in hosts]

    return RedisCluster(
        startup_nodes=startup_nodes,
        password=settings.REDIS_PASSWORD,
    )


def _get_single_redis_client():
    """Get a single Redis client connection."""
    redis_url = build_redis_url()
    return redis.from_url(redis_url)


class BaseRedisWrapperWithPack:
    """
    Base class for Redis storage wrappers with pack/unpack support.

    Provides a dict-like interface for storing JSON-serializable values in Redis
    with automatic TTL. Subclasses only need to override the `db` property to
    provide the appropriate Redis client (Sentinel master, Cluster, etc.).

    Works with PyOP's storage interface for authorization codes, tokens, etc.
    """

    # Override in subclass for logging (e.g., "sentinel", "cluster")
    backend_name: str = "redis"

    def __init__(self, collection: str, ttl: int):
        """Initialize Redis storage.

        Args:
            collection: Key prefix/namespace for this storage
            ttl: Time to live in seconds for stored values
        """
        self._collection = collection
        self.collection = collection  # For compatibility with logging
        self.ttl = ttl
        self._db = None

    @property
    def db(self):
        """Return Redis client. Override in subclass."""
        raise NotImplementedError("Subclasses must implement db property")

    def _key(self, key: str) -> str:
        """Build full Redis key with collection prefix."""
        return f"{self._collection}:{key}"

    def __setitem__(self, key, value):
        """Store a value in Redis with TTL."""
        full_key = self._key(key)
        self.db.set(full_key, json.dumps(value), ex=self.ttl)

    def __getitem__(self, key):
        """Retrieve a value from Redis."""
        full_key = self._key(key)
        value = self.db.get(full_key)
        if value is None:
            raise KeyError(key)
        return json.loads(value)

    def __delitem__(self, key):
        """Delete a value from Redis."""
        full_key = self._key(key)
        self.db.delete(full_key)

    def __contains__(self, key):
        """Check if a key exists in Redis."""
        full_key = self._key(key)
        return self.db.exists(full_key) > 0

    def keys(self):
        """Return all keys in this collection."""
        pattern = f"{self._collection}:*"
        prefix_len = len(self._collection) + 1  # +1 for the colon
        for full_key in self.db.scan_iter(match=pattern):
            # Decode bytes to string if needed
            if isinstance(full_key, bytes):
                full_key = full_key.decode("utf-8")
            # Strip the collection prefix to get the original key
            yield full_key[prefix_len:]

    def values(self):
        """Return all values in this collection."""
        for key in self.keys():
            try:
                yield self[key]
            except KeyError:
                # Key may have expired between scan and get
                continue

    def items(self):
        """Return all (key, value) pairs in this collection."""
        for key in self.keys():
            try:
                yield key, self[key]
            except KeyError:
                # Key may have expired between scan and get
                continue

    def pack(self, value):
        """
        Generate a random key, store the value in Redis, and return the key.

        This enables multi-pod deployments - the value is stored in Redis
        where all pods can access it.
        """
        key = secrets.token_urlsafe(32)
        self[key] = value
        logger.debug(
            f"Stored value in Redis ({self.backend_name})",
            operation="pack",
            collection=self._collection,
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
                f"Retrieved value from Redis ({self.backend_name})",
                operation="unpack",
                collection=self.collection,
                key_prefix=key[:8],
            )
            return value
        except KeyError:
            logger.warning(
                f"Key not found in Redis ({self.backend_name})",
                operation="unpack",
                collection=self.collection,
                key_prefix=key[:8],
            )
            raise


class SentinelRedisWrapperWithPack(BaseRedisWrapperWithPack):
    """Redis storage wrapper using Sentinel for high availability."""

    backend_name = "sentinel"

    @property
    def db(self):
        """Lazy initialization of Sentinel master connection."""
        if self._db is None:
            self._db = _get_sentinel_master()
        return self._db


class ClusterRedisWrapperWithPack(BaseRedisWrapperWithPack):
    """Redis storage wrapper using Redis Cluster for horizontal scaling."""

    backend_name = "cluster"

    @property
    def db(self):
        """Lazy initialization of Cluster client."""
        if self._db is None:
            self._db = _get_cluster_client()
        return self._db


class SingleRedisWrapperWithPack(BaseRedisWrapperWithPack):
    """Redis storage wrapper using a single Redis instance."""

    backend_name = "single"

    @property
    def db(self):
        """Lazy initialization of single Redis connection."""
        if self._db is None:
            self._db = _get_single_redis_client()
        return self._db


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
    logger.info("pem file already exists")
logger.info(f"pem file located at {SIGNING_KEY_FILEPATH}.")

issuer_url = settings.CONTROLLER_URL
if urlparse(issuer_url).scheme != "https":
    logger.warning(
        "CONTROLLER_URL is not HTTPS. changing openid-config for development"
    )
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
        import time

        from api.db.session import COLLECTION_NAMES

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
UserInfoUriEndpoint = "userinfo"

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

# Conditionally add UserInfo endpoint to discovery
if settings.CONTROLLER_ENABLE_USERINFO_ENDPOINT:
    configuration_information["userinfo_endpoint"] = (
        f"{issuer_url}/{UserInfoUriEndpoint}"
    )
    logger.info("OIDC UserInfo endpoint enabled in discovery document")
else:
    logger.info("OIDC UserInfo endpoint disabled in discovery document")


subject_id_factory = HashBasedSubjectIdentifierFactory(settings.SUBJECT_ID_HASH_SALT)


def extract_storage_class(redis_mode: str) -> type[BaseRedisWrapperWithPack]:
    match redis_mode:
        case "sentinel":
            return SentinelRedisWrapperWithPack
        case "cluster":
            return ClusterRedisWrapperWithPack
        case _:
            return SingleRedisWrapperWithPack


# Conditionally create storage backends based on USE_REDIS_ADAPTER setting
if settings.USE_REDIS_ADAPTER:
    # Redis storage for multi-pod deployments - shared state across all pods
    redis_mode = settings.REDIS_MODE.lower()

    storage_class: type[BaseRedisWrapperWithPack] = extract_storage_class(redis_mode)
    authorization_code_storage = storage_class(
        collection="pyop_authorization_codes",
        ttl=600,  # 10 minutes
    )

    access_token_storage = storage_class(
        collection="pyop_access_tokens",
        ttl=settings.OIDC_ACCESS_TOKEN_TTL,
    )

    refresh_token_storage = storage_class(
        collection="pyop_refresh_tokens",
        ttl=2592000,  # 30 days
    )

    subject_identifier_storage = storage_class(
        collection="pyop_subject_identifiers",
        ttl=3600,  # 1 hour - matches access token lifetime
    )

    userinfo_claims_storage = storage_class(
        collection="pyop_userinfo_claims",
        # Set TTL to match Token TTL.
        # We add a 60 second buffer to ensure the data strictly outlives the token
        # preventing race conditions at the exact second of expiry.
        ttl=settings.OIDC_ACCESS_TOKEN_TTL + 60,
    )

    logger.info(
        f"Initialized Redis {storage_class.backend_name} storage for PyOP tokens",
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
    userinfo_claims_storage = {}  # In-memory dict for single-pod

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
        VCUserinfo({}, claims_storage=userinfo_claims_storage),
    )
