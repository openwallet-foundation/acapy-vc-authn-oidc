"""Integration test fixtures and helpers.

Strategy
--------
- mongomock replaces real MongoDB (session-scoped client, function-scoped DB reset).
- patch.object(api.db.session, "client", mock_mongo) ensures the startup event's
  init_db() / init_provider() use the mock database.
- app.dependency_overrides[get_db] ensures route handlers get the same mock DB.
- respx.mock (per test) intercepts AcaPy HTTP calls made through app.state.http_client.
- settings overrides are done via pytest's monkeypatch fixture per test.
"""

import asyncio
import os
import re
import uuid
from contextlib import contextmanager
from unittest.mock import patch

import httpx
import mongomock
import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response

import api.db.session as db_session_module
from api.core.config import settings
from api.db.collections import COLLECTION_NAMES
from api.db.session import get_db
from api.main import app


# ---------------------------------------------------------------------------
# Minimal Jinja2 template: exposes pid and pres_exch_id for test parsing
# ---------------------------------------------------------------------------

_TEST_TEMPLATE = (
    "<html><body>pid={{ pid }} pres_exch_id={{ pres_exch_id }}</body></html>"
)


@pytest.fixture(scope="session", autouse=True)
def _controller_template_dir(tmp_path_factory):
    """Create verified_credentials.html in a temp dir and point settings to it.

    session-scoped + autouse guarantees this runs before any TestClient fixture
    triggers the app lifespan startup event, which calls
    StaticFiles(directory=settings.CONTROLLER_TEMPLATE_DIR + "/assets") and
    requires that directory to already exist.
    """
    tmp_dir = tmp_path_factory.mktemp("controller_templates")
    assets_dir = tmp_dir / "assets"
    assets_dir.mkdir()
    template_path = tmp_dir / "verified_credentials.html"
    template_path.write_text(_TEST_TEMPLATE)
    settings.CONTROLLER_TEMPLATE_DIR = str(tmp_dir)


# ---------------------------------------------------------------------------
# Verification-mode fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def oob_mode(monkeypatch):
    """Set OOB (out-of-band, connectionless) verification mode for the test."""
    monkeypatch.setattr(settings, "USE_CONNECTION_BASED_VERIFICATION", False)


@pytest.fixture
def connection_mode(monkeypatch):
    """Set connection-based verification mode for the test."""
    monkeypatch.setattr(settings, "USE_CONNECTION_BASED_VERIFICATION", True)


# ---------------------------------------------------------------------------
# Shared auth helpers
# ---------------------------------------------------------------------------


def basic_auth_header(client_id: str, secret: str) -> str:
    """Build an HTTP Basic Authorization header value."""
    import base64

    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


# ---------------------------------------------------------------------------
# Test-data constants
# ---------------------------------------------------------------------------

TEST_CLIENT_ID = "test-integration-client"
TEST_CLIENT_SECRET = "test-integration-secret"
TEST_REDIRECT_URI = "http://localhost:9999/callback"
TEST_VER_CONFIG_ID = "test-ver-config"

FAKE_PRES_EX_ID = "aabbccdd-1122-3344-5566-aabbccddeeff"
FAKE_INVI_MSG_ID = "ccddee00-3344-5566-7788-ccddee001122"
TEST_CONNECTION_ID = "real-conn-id-test-1234"

ACAPY_BASE = settings.ACAPY_ADMIN_URL


# ---------------------------------------------------------------------------
# MongoDB fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def _mock_mongo():
    """Session-scoped mongomock client shared by all integration tests."""
    return mongomock.MongoClient()


@pytest.fixture
def integration_db(_mock_mongo):
    """Function-scoped: clear all collections, then yield the mock DB."""
    db = _mock_mongo[settings.DB_NAME]
    for col in (
        COLLECTION_NAMES.AUTH_SESSION,
        COLLECTION_NAMES.VER_CONFIGS,
        COLLECTION_NAMES.CLIENT_CONFIGURATIONS,
    ):
        db.get_collection(col).delete_many({})
    return db


# ---------------------------------------------------------------------------
# Seed helpers (insert test data directly into mongomock)
# ---------------------------------------------------------------------------


def seed_client_config(db) -> None:
    db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS).insert_one(
        {
            "client_id": TEST_CLIENT_ID,
            "client_name": "Integration Test Client",
            "client_secret": TEST_CLIENT_SECRET,
            "redirect_uris": [TEST_REDIRECT_URI],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
        }
    )


def seed_ver_config(db) -> None:
    db.get_collection(COLLECTION_NAMES.VER_CONFIGS).insert_one(
        {
            "ver_config_id": TEST_VER_CONFIG_ID,
            "subject_identifier": "first_name",
            "generate_consistent_identifier": False,
            "include_v1_attributes": False,
            "proof_request": {
                "name": "Test Proof",
                "version": "1.0",
                "requested_attributes": [
                    {
                        "names": ["first_name", "last_name"],
                        "restrictions": [],
                    }
                ],
                "requested_predicates": [],
            },
        }
    )


# ---------------------------------------------------------------------------
# Full-app TestClient fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def integration_client(integration_db, _mock_mongo):
    """TestClient wrapping the full FastAPI app.

    - MongoDB is replaced with mongomock for both startup events and route handlers.
    - OIDC client + ver_config are seeded before the client starts.
    - Yields (TestClient, db) so tests can inspect DB state.
    """
    seed_client_config(integration_db)
    seed_ver_config(integration_db)

    app.dependency_overrides[get_db] = lambda: integration_db

    # Patch api.db.session.client so init_db() and init_provider() in the startup
    # event use mongomock instead of the real MongoDB connection.
    with patch.object(db_session_module, "client", _mock_mongo):
        with TestClient(app, raise_server_exceptions=True) as client:
            yield client, integration_db

    app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# AcaPy respx mock builders
# ---------------------------------------------------------------------------


@contextmanager
def acapy_oob_mock(pres_ex_id: str = FAKE_PRES_EX_ID):
    """Context manager that replaces app.state.http_client with a respx-backed mock
    pre-configured for the OOB (out-of-band) AcaPy calls."""
    router = respx.MockRouter(assert_all_called=False, assert_all_mocked=False)

    # 1. POST /present-proof-2.0/create-request
    router.post(f"{ACAPY_BASE}/present-proof-2.0/create-request").mock(
        return_value=Response(
            200,
            json={
                "thread_id": str(uuid.uuid4()),
                "pres_ex_id": pres_ex_id,
                "pres_request": {
                    "indy": {
                        "name": "Test Proof",
                        "version": "1.0",
                        "requested_attributes": {
                            "req_attr_0": {
                                "names": ["first_name", "last_name"],
                                "restrictions": [],
                            }
                        },
                        "requested_predicates": {},
                    }
                },
            },
        )
    )

    # 2. POST /out-of-band/create-invitation
    router.post(f"{ACAPY_BASE}/out-of-band/create-invitation").mock(
        return_value=Response(
            200,
            json={
                "invi_msg_id": FAKE_INVI_MSG_ID,
                "invitation_url": "http://example.com/invite?oob=abc123",
                "oob_id": str(uuid.uuid4()),
                "trace": False,
                "state": "initial",
                "invitation": {
                    "@id": str(uuid.uuid4()),
                    "@type": "https://didcomm.org/out-of-band/1.1/invitation",
                    "goal_code": "aries.vc.verifier.once",
                    "label": "VC-AuthN",
                    "services": ["did:sov:test123"],
                },
            },
        )
    )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(router.handler))
    original = getattr(app.state, "http_client", None)
    app.state.http_client = mock_client
    try:
        yield router
    finally:
        app.state.http_client = original
        asyncio.run(mock_client.aclose())


@contextmanager
def acapy_connection_mock(
    invi_msg_id: str = FAKE_INVI_MSG_ID,
    pres_ex_id: str = FAKE_PRES_EX_ID,
    connection_id: str = TEST_CONNECTION_ID,
):
    """Context manager that replaces app.state.http_client with a respx-backed mock
    pre-configured for connection-based AcaPy calls."""
    router = respx.MockRouter(assert_all_called=False, assert_all_mocked=False)

    # 1. POST /out-of-band/create-invitation (create_connection_invitation)
    router.post(f"{ACAPY_BASE}/out-of-band/create-invitation").mock(
        return_value=Response(
            200,
            json={
                "invi_msg_id": invi_msg_id,
                "invitation_url": "http://example.com/invite?oob=conn123",
                "oob_id": str(uuid.uuid4()),
                "trace": False,
                "state": "initial",
                "invitation": {
                    "@id": invi_msg_id,
                    "@type": "https://didcomm.org/out-of-band/1.1/invitation",
                    "goal_code": "aries.vc.verify.once",
                    "label": "VC-AuthN",
                    "handshake_protocols": [
                        "https://didcomm.org/didexchange/1.0",
                        "https://didcomm.org/connections/1.0",
                    ],
                    "services": ["did:sov:test123"],
                },
            },
        )
    )

    # 2. POST /present-proof-2.0/send-request (send_presentation_request_by_connection)
    router.post(f"{ACAPY_BASE}/present-proof-2.0/send-request").mock(
        return_value=Response(
            200,
            json={
                "thread_id": str(uuid.uuid4()),
                "pres_ex_id": pres_ex_id,
                "pres_request": {
                    "indy": {
                        "name": "Test Proof",
                        "version": "1.0",
                        "requested_attributes": {
                            "req_attr_0": {
                                "names": ["first_name", "last_name"],
                                "restrictions": [],
                            }
                        },
                        "requested_predicates": {},
                    }
                },
            },
        )
    )

    # 3. DELETE /connections/{id} (cleanup after verification)
    router.delete(f"{ACAPY_BASE}/connections/{connection_id}").mock(
        return_value=Response(200, json={})
    )

    # 4. POST problem-report (called on failure/abandon in connection mode)
    router.post(
        url__regex=rf"{re.escape(ACAPY_BASE)}/present-proof-2.0/records/.*/problem-report"
    ).mock(return_value=Response(200, json={}))

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(router.handler))
    original = getattr(app.state, "http_client", None)
    app.state.http_client = mock_client
    try:
        yield router
    finally:
        app.state.http_client = original
        asyncio.run(mock_client.aclose())


# ---------------------------------------------------------------------------
# Webhook payload builder
# ---------------------------------------------------------------------------


def make_proof_webhook(
    pres_ex_id: str,
    verified: bool = True,
    state: str = "done",
    role: str = "verifier",
) -> dict:
    """Build a present_proof_v2_0 webhook payload with realistic presentation data."""
    payload = {
        "pres_ex_id": pres_ex_id,
        "state": state,
        "role": role,
        "verified": "true" if verified else "false",
    }

    if state in ("done",):
        payload["by_format"] = {
            "pres_request": {
                "indy": {
                    "name": "Test Proof",
                    "version": "1.0",
                    "requested_attributes": {
                        "req_attr_0": {
                            "names": ["first_name", "last_name"],
                            "restrictions": [],
                        }
                    },
                    "requested_predicates": {},
                }
            },
            "pres": {
                "indy": {
                    "requested_proof": {
                        "revealed_attr_groups": {
                            "req_attr_0": {
                                "sub_proof_index": 0,
                                "values": {
                                    "first_name": {
                                        "raw": "Alice",
                                        "encoded": "27034640024117915420249886609744890745396057622",
                                    },
                                    "last_name": {
                                        "raw": "Smith",
                                        "encoded": "76402217395101400862778225684189168718754338379",
                                    },
                                },
                            }
                        }
                    }
                }
            },
        }

    return payload


def make_abandoned_webhook(pres_ex_id: str) -> dict:
    return {
        "pres_ex_id": pres_ex_id,
        "state": "abandoned",
        "role": "verifier",
        "verified": "false",
        "error_msg": "presentation abandoned by holder",
    }


# ---------------------------------------------------------------------------
# HTML / URL parsing helpers
# ---------------------------------------------------------------------------


def parse_pid_from_html(html: str) -> str:
    """Extract pid (MongoDB ObjectId) from the test template HTML."""
    match = re.search(r"pid=([a-f0-9]{24})", html)
    if not match:
        raise ValueError(f"Could not find pid in HTML response: {html[:300]!r}")
    return match.group(1)


def parse_pres_exch_id_from_html(html: str) -> str:
    """Extract pres_exch_id from the test template HTML."""
    match = re.search(r"pres_exch_id=([^\s<]+)", html)
    if not match:
        raise ValueError(
            f"Could not find pres_exch_id in HTML response: {html[:300]!r}"
        )
    return match.group(1)


def parse_auth_code_from_url(url: str) -> str:
    """Extract the authorization code from an OIDC redirect URL."""
    match = re.search(r"[?&]code=([^&]+)", url)
    if not match:
        raise ValueError(f"Could not find code in redirect URL: {url!r}")
    return match.group(1)


# ---------------------------------------------------------------------------
# OIDC authorize params helper
# ---------------------------------------------------------------------------


def authorize_params(
    client_id: str = TEST_CLIENT_ID,
    redirect_uri: str = TEST_REDIRECT_URI,
    ver_config_id: str = TEST_VER_CONFIG_ID,
    state: str = "test-state",
    nonce: str = "test-nonce",
) -> dict:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "pres_req_conf_id": ver_config_id,
        "state": state,
        "nonce": nonce,
    }


def parse_sse_status(text: str) -> str:
    """Parse an SSE response body and return the status from the last status event.

    Validates the SSE wire format (event: status / data: {...}) rather than doing
    a substring match, catching malformed events and keepalive false-positives.

    Returns the *last* status event because the stream may emit an initial
    NOT_STARTED event followed by the terminal state (e.g. when the session
    expires on-connect: the stream emits NOT_STARTED then expired).
    """
    import json as _json

    last_status = None
    for block in text.split("\n\n"):
        event_type = data = None
        for line in block.strip().splitlines():
            if line.startswith("event: "):
                event_type = line[7:].strip()
            elif line.startswith("data: "):
                data = line[6:].strip()
        if event_type == "status" and data:
            last_status = _json.loads(data)["status"]
    if last_status is not None:
        return last_status
    raise ValueError(f"No status event found in SSE response: {text!r}")


def called_paths(mock_router) -> list[str]:
    """Return the URL path of every HTTP call recorded by a respx MockRouter."""
    return [c.request.url.path for c in mock_router.calls]
