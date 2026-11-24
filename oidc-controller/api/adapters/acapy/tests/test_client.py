import json
from unittest import mock

import httpx
import pytest
import respx
from api.adapters.acapy.client import (
    CONNECTIONS_URI,
    CREATE_PRESENTATION_REQUEST_URL,
    OOB_CREATE_INVITATION,
    PRESENT_PROOF_PROBLEM_REPORT_URL,
    SEND_PRESENTATION_REQUEST_URL,
    AcapyClient,
    AcapyError,
)
from api.adapters.acapy.config import (
    MultiTenantAcapy,
    SingleTenantAcapy,
    TractionTenantAcapy,
)
from api.adapters.acapy.tests.__mocks__ import (
    create_presentation_response_http,
    presentation_request_configuration,
)
from api.config import settings
from api.core.acapy.models import CreatePresentationResponse


@pytest.fixture
def http_client():
    return httpx.AsyncClient()


@pytest.mark.asyncio
@mock.patch.object(settings, "ACAPY_TENANCY", None)
async def test_init_no_setting_returns_client_with_single_tenancy_config(http_client):
    client = AcapyClient(http_client)
    assert client is not None
    assert isinstance(client.agent_config, SingleTenantAcapy) is True


@pytest.mark.asyncio
@mock.patch.object(settings, "ACAPY_TENANCY", "single")
async def test_init_single_returns_client_with_single_tenancy_config(http_client):
    client = AcapyClient(http_client)
    assert client is not None
    assert isinstance(client.agent_config, SingleTenantAcapy) is True


@pytest.mark.asyncio
@mock.patch.object(settings, "ACAPY_TENANCY", "multi")
async def test_init_multi_returns_client_with_multi_tenancy_config(http_client):
    client = AcapyClient(http_client)
    assert client is not None
    assert isinstance(client.agent_config, MultiTenantAcapy) is True


@pytest.mark.asyncio
@mock.patch.object(settings, "ACAPY_TENANCY", "traction")
async def test_init_traction_returns_client_with_traction_tenancy_config(http_client):
    client = AcapyClient(http_client)
    assert client is not None
    assert isinstance(client.agent_config, TractionTenantAcapy) is True


@pytest.mark.asyncio
@respx.mock
async def test_create_presentation_returns_sucessfully_with_valid_data(http_client):
    respx.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(200, json=create_presentation_response_http))

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        presentation_request = await client.create_presentation_request(
            presentation_request_configuration
        )
        assert presentation_request is not None


@pytest.mark.asyncio
@respx.mock
async def test_presentation_requests_ask_acapy_to_auto_remove_records(http_client):
    create_route = respx.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(200, json=create_presentation_response_http))
    send_route = respx.post(
        settings.ACAPY_ADMIN_URL + SEND_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(200, json=create_presentation_response_http))

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        await client.create_presentation_request(presentation_request_configuration)
        await client.send_presentation_request_by_connection(
            "conn-1", presentation_request_configuration
        )

    for route in (create_route, send_route):
        body = json.loads(route.calls[0].request.content)
        assert body["auto_remove"] is True
        assert body["auto_remove_on_failure"] is True


@pytest.mark.asyncio
@respx.mock
async def test_create_presentation_returns_error_with_non_200_resp_from_acapy(
    http_client,
):
    respx.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(400, json=create_presentation_response_http))

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        result = await client.create_presentation_request(
            presentation_request_configuration
        )
        assert isinstance(result, AcapyError)


@pytest.mark.asyncio
@respx.mock
async def test_create_presentation_returns_error_with_non_json_from_acapy(http_client):
    respx.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(200))

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        result = await client.create_presentation_request(
            presentation_request_configuration
        )
        assert isinstance(result, AcapyError)


# Connection-based verification tests
@pytest.mark.asyncio
@respx.mock
async def test_send_presentation_request_by_connection_returns_successfully(
    http_client,
):
    """Test that send_presentation_request_by_connection returns successfully with valid data."""
    connection_id = "test-connection-id"
    presentation_request_config = {"test": "config"}

    respx.post(
        settings.ACAPY_ADMIN_URL + SEND_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(200, json=create_presentation_response_http))

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        result = await client.send_presentation_request_by_connection(
            connection_id=connection_id,
            presentation_request_configuration=presentation_request_config,
        )
        assert result is not None


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "reply",
    [
        httpx.Response(400, text="bad request"),
        httpx.Response(200, json={"unexpected": "shape"}),
        httpx.ConnectError("refused"),
    ],
    ids=["non-200", "bad-reply", "unreachable"],
)
async def test_send_presentation_request_by_connection_returns_error_value(
    http_client, reply
):
    route = respx.post(settings.ACAPY_ADMIN_URL + SEND_PRESENTATION_REQUEST_URL)
    if isinstance(reply, Exception):
        route.mock(side_effect=reply)
    else:
        route.mock(return_value=reply)
    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})

    result = await client.send_presentation_request_by_connection(
        connection_id="test-connection-id",
        presentation_request_configuration={"test": "config"},
    )

    assert isinstance(result, AcapyError)


@pytest.mark.asyncio
@respx.mock
async def test_delete_connection_returns_none_on_successful_deletion(http_client):
    connection_id = "test-connection-id"

    respx.delete(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
    ).mock(return_value=httpx.Response(200))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.delete_connection(connection_id)
    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_delete_connection_returns_error_on_failed_deletion(http_client):
    connection_id = "test-connection-id"

    respx.delete(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
    ).mock(return_value=httpx.Response(500))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.delete_connection(connection_id)
    assert isinstance(result, AcapyError)


@pytest.mark.asyncio
@respx.mock
async def test_delete_connection_returns_none_when_already_gone(http_client):
    """Test that delete_connection treats a missing connection as deleted."""
    connection_id = "test-connection-id"

    respx.delete(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
    ).mock(return_value=httpx.Response(404))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.delete_connection(connection_id)
    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_create_connection_invitation_ephemeral_returns_successfully(
    http_client,
):
    """Test that create_connection_invitation returns successfully for ephemeral connections."""
    expected_response = {
        "invitation_url": "http://example.com/invitation",
        "invitation": {
            "@type": "invitation",
            "@id": "test-invitation-id",
            "services": ["did:example:123"],
        },
        "invi_msg_id": "test-invitation-id",
        "oob_id": "test-oob-id",
        "trace": False,
        "state": "initial",
    }

    route = respx.post(
        settings.ACAPY_ADMIN_URL + OOB_CREATE_INVITATION,
    ).mock(return_value=httpx.Response(200, json=expected_response))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.create_connection_invitation(multi_use=False)
    assert result is not None

    # Verify the request payload for ephemeral connection
    request_payload = json.loads(route.calls.last.request.content)
    assert "handshake_protocols" in request_payload
    assert "goal_code" in request_payload
    assert request_payload["goal_code"] == "aries.vc.verify.once"


@pytest.mark.asyncio
@respx.mock
async def test_create_connection_invitation_persistent_returns_successfully(
    http_client,
):
    """Test that create_connection_invitation returns successfully for persistent connections."""
    expected_response = {
        "invitation_url": "http://example.com/invitation",
        "invitation": {
            "@type": "invitation",
            "@id": "test-invitation-id",
            "services": ["did:example:123"],
        },
        "invi_msg_id": "test-invitation-id",
        "oob_id": "test-oob-id",
        "trace": False,
        "state": "initial",
    }

    route = respx.post(
        settings.ACAPY_ADMIN_URL + OOB_CREATE_INVITATION,
    ).mock(return_value=httpx.Response(200, json=expected_response))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.create_connection_invitation(multi_use=True)
    assert result is not None

    # Verify the request payload for persistent connection
    request_payload = json.loads(route.calls.last.request.content)
    assert "handshake_protocols" in request_payload
    assert "goal_code" in request_payload
    assert request_payload["goal_code"] == "aries.vc.verify"


@pytest.mark.asyncio
@respx.mock
async def test_create_connection_invitation_returns_error_on_non_200(http_client):
    respx.post(
        settings.ACAPY_ADMIN_URL + OOB_CREATE_INVITATION,
    ).mock(return_value=httpx.Response(400, json={"error": "Bad request"}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    assert isinstance(await client.create_connection_invitation(), AcapyError)


# Problem report tests
@pytest.mark.asyncio
@respx.mock
async def test_send_problem_report_returns_none_on_200(http_client):
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    respx.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
    ).mock(return_value=httpx.Response(200, json={"success": True}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})

    result = await client.send_problem_report(pres_ex_id, description)
    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_send_problem_report_returns_error_on_non_200_response(http_client):
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    respx.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
    ).mock(return_value=httpx.Response(400, json={"error": "Bad request"}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})

    result = await client.send_problem_report(pres_ex_id, description)
    assert isinstance(result, AcapyError)


@pytest.mark.asyncio
@respx.mock
async def test_send_problem_report_returns_error_when_unreachable(http_client):
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    respx.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
    ).mock(side_effect=httpx.ConnectError("Network error"))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})

    result = await client.send_problem_report(pres_ex_id, description)
    assert isinstance(result, AcapyError)


@pytest.mark.asyncio
@respx.mock
async def test_send_problem_report_sends_correct_payload(http_client):
    """Test that send_problem_report sends the correct payload to ACA-Py."""
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    route = respx.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
    ).mock(return_value=httpx.Response(200, json={"success": True}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})

    result = await client.send_problem_report(pres_ex_id, description)
    assert result is None

    # Verify the request was made with correct parameters
    assert json.loads(route.calls.last.request.content) == {"description": description}
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_create_presentation_request_uses_configured_proof_format(http_client):
    # Verify payload key respects ACAPY_PROOF_FORMAT
    route = respx.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(200, json=create_presentation_response_http))

    # Patch the setting to 'anoncreds'
    with mock.patch.object(settings, "ACAPY_PROOF_FORMAT", "anoncreds"):
        with mock.patch.object(
            CreatePresentationResponse,
            "model_validate",
            return_value={"result": "success"},
        ):
            client = AcapyClient(http_client)
            client.agent_config.get_headers = mock.AsyncMock(
                return_value={"x-api-key": ""}
            )

            await client.create_presentation_request(presentation_request_configuration)

            # Inspect the actual JSON body sent to ACA-Py
            request_json = json.loads(route.calls.last.request.content)
            assert "anoncreds" in request_json["presentation_request"]
            assert "indy" not in request_json["presentation_request"]


@pytest.mark.asyncio
@respx.mock
async def test_send_presentation_request_by_connection_uses_configured_proof_format(
    http_client,
):
    # Verify connection-based request also respects ACAPY_PROOF_FORMAT
    route = respx.post(
        settings.ACAPY_ADMIN_URL + SEND_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(200, json=create_presentation_response_http))

    with mock.patch.object(settings, "ACAPY_PROOF_FORMAT", "anoncreds"):
        with mock.patch.object(
            CreatePresentationResponse,
            "model_validate",
            return_value={"result": "success"},
        ):
            client = AcapyClient(http_client)
            client.agent_config.get_headers = mock.AsyncMock(
                return_value={"x-api-key": ""}
            )

            await client.send_presentation_request_by_connection(
                "conn_id", presentation_request_configuration
            )

            request_json = json.loads(route.calls.last.request.content)
            assert "anoncreds" in request_json["presentation_request"]
            assert "indy" not in request_json["presentation_request"]
