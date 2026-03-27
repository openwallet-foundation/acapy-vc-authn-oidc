"""E2E test fixtures.

Prerequisites:
  1. Run `docker compose -f docker/docker-compose.yaml -f docker/docker-compose-e2e.yaml up -d`
  2. Run `python scripts/bootstrap-test-holder.py`
     → writes tests/e2e/bootstrap_output.json

Environment variables (with defaults):
  CONTROLLER_URL     http://localhost:5000
  HOLDER_ADMIN_URL   http://localhost:8079
  ISSUER_ADMIN_URL   http://localhost:8078
  CONTROLLER_API_KEY (empty by default — no key required)
  E2E_CLIENT_ID      e2e-test-client
  E2E_CLIENT_SECRET  e2e-test-secret
  E2E_REDIRECT_URI   http://localhost:9999/callback

Tests are skipped automatically when the controller is not reachable.
"""

import json
import os
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from .helpers.aca_py import AcaPyAdminClient
from .helpers.oidc_client import OIDCFlowClient
from .helpers.sse_client import SSEClient


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONTROLLER_URL = os.getenv("CONTROLLER_URL", "http://localhost:5000")
HOLDER_ADMIN_URL = os.getenv("HOLDER_ADMIN_URL", "http://localhost:8079")
ISSUER_ADMIN_URL = os.getenv("ISSUER_ADMIN_URL", "http://localhost:8078")
CONTROLLER_API_KEY = os.getenv("CONTROLLER_API_KEY", "")

E2E_CLIENT_ID = os.getenv("E2E_CLIENT_ID", "e2e-test-client")
E2E_CLIENT_SECRET = os.getenv("E2E_CLIENT_SECRET", "e2e-test-secret")
E2E_REDIRECT_URI = os.getenv("E2E_REDIRECT_URI", "http://localhost:9999/callback")

BOOTSTRAP_OUTPUT = Path(__file__).parent / "bootstrap_output.json"

# ---------------------------------------------------------------------------
# Skip helper
# ---------------------------------------------------------------------------


def _controller_available() -> bool:
    try:
        httpx.get(f"{CONTROLLER_URL}/health", timeout=3.0)
        return True
    except httpx.RequestError:
        return False


def _holder_available() -> bool:
    try:
        httpx.get(f"{HOLDER_ADMIN_URL}/status", timeout=3.0)
        return True
    except httpx.RequestError:
        return False


# ---------------------------------------------------------------------------
# Session-scoped: bootstrap output
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def bootstrap_output() -> dict:
    """Read the JSON written by scripts/bootstrap-test-holder.py."""
    if not BOOTSTRAP_OUTPUT.exists():
        pytest.skip(
            f"Bootstrap output not found at {BOOTSTRAP_OUTPUT}. "
            "Run: python scripts/bootstrap-test-holder.py"
        )
    return json.loads(BOOTSTRAP_OUTPUT.read_text())


@pytest.fixture(scope="session")
def cred_def_id(bootstrap_output) -> str:
    return bootstrap_output["cred_def_id"]


@pytest.fixture(scope="session")
def holder_credential_values(bootstrap_output) -> dict:
    return bootstrap_output["credential_values"]


# ---------------------------------------------------------------------------
# Session-scoped: OIDC client registration
# ---------------------------------------------------------------------------


def _api_headers() -> dict:
    h = {}
    if CONTROLLER_API_KEY:
        h["x-api-key"] = CONTROLLER_API_KEY
    return h


@pytest.fixture(scope="session")
def e2e_client_id() -> str:
    """Register an OIDC client with the controller (idempotent by client_id)."""
    if not _controller_available():
        pytest.skip(f"Controller not reachable at {CONTROLLER_URL}")

    payload = {
        "client_id": E2E_CLIENT_ID,
        "client_name": "E2E Test Client",
        "client_secret": E2E_CLIENT_SECRET,
        "redirect_uris": [E2E_REDIRECT_URI],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
    }
    r = httpx.post(
        f"{CONTROLLER_URL}/clients/",
        json=payload,
        headers=_api_headers(),
        timeout=10.0,
    )
    if r.status_code == 409:
        # Already registered — use existing
        pass
    else:
        r.raise_for_status()
    return E2E_CLIENT_ID


@pytest.fixture(scope="session")
def e2e_ver_config_id(e2e_client_id, cred_def_id) -> str:
    """Create a verification config restricted to the bootstrapped cred_def_id."""
    ver_config_id = f"e2e-test-config-{uuid.uuid4().hex[:8]}"
    payload = {
        "ver_config_id": ver_config_id,
        "subject_identifier": "first_name",
        "generate_consistent_identifier": False,
        "include_v1_attributes": False,
        "proof_request": {
            "name": "E2E Test Proof",
            "version": "1.0",
            "requested_attributes": [
                {
                    "names": ["first_name", "last_name"],
                    "restrictions": [{"cred_def_id": cred_def_id}],
                }
            ],
            "requested_predicates": [],
        },
    }
    r = httpx.post(
        f"{CONTROLLER_URL}/ver_configs/",
        json=payload,
        headers=_api_headers(),
        timeout=10.0,
    )
    r.raise_for_status()
    return ver_config_id


# ---------------------------------------------------------------------------
# Function-scoped: per-test helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def oidc_client(e2e_client_id, e2e_ver_config_id) -> OIDCFlowClient:
    if not _controller_available():
        pytest.skip(f"Controller not reachable at {CONTROLLER_URL}")
    return OIDCFlowClient(
        controller_url=CONTROLLER_URL,
        client_id=E2E_CLIENT_ID,
        client_secret=E2E_CLIENT_SECRET,
        redirect_uri=E2E_REDIRECT_URI,
    )


@pytest.fixture
def holder_admin() -> AcaPyAdminClient:
    if not _holder_available():
        pytest.skip(f"Holder agent not reachable at {HOLDER_ADMIN_URL}")
    return AcaPyAdminClient(admin_url=HOLDER_ADMIN_URL)


@pytest.fixture
def sse_client() -> SSEClient:
    return SSEClient(controller_url=CONTROLLER_URL)


@pytest.fixture
def ver_config_id(e2e_ver_config_id) -> str:
    return e2e_ver_config_id
