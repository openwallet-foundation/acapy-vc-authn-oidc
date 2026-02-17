"""Shared Redis utilities for connection management across modules.

Used by:
- api/routers/socketio.py (Socket.IO Redis adapter)
- api/core/oidc/provider.py (PyOP token storage)
- api/main.py (startup health checks)
"""


import structlog

from api.core.config import settings

logger = structlog.getLogger(__name__)


def parse_host_port_pairs(hosts_string: str) -> list[tuple[str, int]]:
    """Parse 'host1:port1,host2:port2' into list of (host, port) tuples.

    Filters out empty entries (e.g., from "host1:6379,,host2:6379").

    Args:
        hosts_string: Comma-separated host:port pairs

    Returns:
        List of (host, port) tuples
    """
    nodes = []
    for node in hosts_string.split(","):
        node = node.strip()
        if not node:
            continue
        host, port = node.rsplit(":", 1)
        nodes.append((host, int(port)))
    return nodes


def build_redis_url() -> str | None:
    """Build Redis connection URL from settings based on REDIS_MODE.

    Returns:
        str | None: Redis URL for single/sentinel modes, None for cluster mode
                    (cluster uses parse_host_port_pairs directly)

    URL Formats:
        - single: redis://[:password@]host:port/db
        - sentinel: redis+sentinel://[:password@]host1:port1,host2:port2/master_name/db
        - cluster: Returns None (uses parse_host_port_pairs instead)
    """
    mode = settings.REDIS_MODE.lower()

    if mode == "single":
        if settings.REDIS_PASSWORD:
            return f"redis://:{settings.REDIS_PASSWORD}@{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
        return f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"

    elif mode == "sentinel":
        nodes = settings.REDIS_HOST
        master = settings.REDIS_SENTINEL_MASTER_NAME
        if settings.REDIS_PASSWORD:
            return f"redis+sentinel://:{settings.REDIS_PASSWORD}@{nodes}/{master}/{settings.REDIS_DB}"
        return f"redis+sentinel://{nodes}/{master}/{settings.REDIS_DB}"

    # Cluster and other modes don't use URL format
    return None
