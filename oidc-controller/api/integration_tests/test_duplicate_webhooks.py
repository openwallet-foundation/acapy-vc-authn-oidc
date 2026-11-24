"""Integration tests: ACA-Py delivers the same webhook twice.

ACA-Py retries webhooks, and with several controller pods two deliveries can
be handled by different pods. A repeated webhook must not repeat the side
effects of the first: the audit event, the SSE notification and the problem
report sent to the wallet.
"""

from unittest.mock import patch

import pytest

from .conftest import (
    FAKE_PRES_EX_ID,
    acapy_connection_mock,
    acapy_oob_mock,
    authorize_params,
    make_abandoned_webhook,
    make_connections_webhook,
    make_proof_webhook,
)

pytestmark = pytest.mark.integration

PROOF_TOPIC = "/webhooks/topic/present_proof_v2_0/"


def _post_twice(client, topic: str, body: dict) -> None:
    for _ in range(2):
        assert client.post(topic, json=body).status_code == 200


@pytest.mark.parametrize(
    ("body", "audit", "status"),
    [
        (
            make_proof_webhook(FAKE_PRES_EX_ID, verified=True),
            "audit_proof_verified",
            "verified",
        ),
        (
            make_proof_webhook(FAKE_PRES_EX_ID, verified=False),
            "audit_proof_verification_failed",
            "failed",
        ),
        (
            make_abandoned_webhook(FAKE_PRES_EX_ID),
            "audit_session_abandoned",
            "abandoned",
        ),
    ],
    ids=["verified", "failed", "abandoned"],
)
def test_repeated_proof_webhook_has_its_effects_once(
    integration_client, oob_mode, body, audit, status
):
    client, _ = integration_client
    with acapy_oob_mock():
        client.get("/authorize", params=authorize_params())

    with (
        patch(f"api.routers.acapy_handler.{audit}") as mock_audit,
        patch("api.routers.acapy_handler.notify") as mock_notify,
    ):
        _post_twice(client, PROOF_TOPIC, body)

    mock_audit.assert_called_once()
    assert [c.args[1] for c in mock_notify.await_args_list] == [status]


@pytest.mark.parametrize(
    "body",
    [
        make_proof_webhook(FAKE_PRES_EX_ID, verified=False),
        make_abandoned_webhook(FAKE_PRES_EX_ID),
    ],
    ids=["failed", "abandoned"],
)
def test_repeated_proof_webhook_sends_one_problem_report(
    integration_client, connection_mode, body
):
    client, _ = integration_client
    with acapy_connection_mock() as router:
        client.get("/authorize", params=authorize_params())
        client.post("/webhooks/topic/connections/", json=make_connections_webhook())

        _post_twice(client, PROOF_TOPIC, body)

    reports = [
        c for c in router.calls if c.request.url.path.endswith("/problem-report")
    ]
    assert len(reports) == 1


@pytest.mark.xfail(
    strict=True,
    reason="#1155: a repeated connections webhook sends a second proof request",
)
def test_repeated_connections_webhook_sends_one_proof_request(
    integration_client, connection_mode
):
    client, _ = integration_client
    with acapy_connection_mock() as router:
        client.get("/authorize", params=authorize_params())

        _post_twice(client, "/webhooks/topic/connections/", make_connections_webhook())

    sends = [c for c in router.calls if c.request.url.path.endswith("/send-request")]
    assert len(sends) == 1
