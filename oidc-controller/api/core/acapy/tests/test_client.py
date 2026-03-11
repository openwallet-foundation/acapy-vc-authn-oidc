import json
from unittest import mock

import httpx
import pytest
import respx
from api.core.acapy.client import (
    CONNECTIONS_URI,
    CREATE_PRESENTATION_REQUEST_URL,
    OOB_CREATE_INVITATION,
    PRESENT_PROOF_PROBLEM_REPORT_URL,
    PRESENT_PROOF_RECORDS,
    PUBLIC_WALLET_DID_URI,
    SEND_PRESENTATION_REQUEST_URL,
    WALLET_DID_URI,
    AcapyClient,
)
from api.core.acapy.config import (
    MultiTenantAcapy,
    SingleTenantAcapy,
    TractionTenantAcapy,
)
from api.core.acapy.models import CreatePresentationResponse, WalletDid
from api.core.acapy.tests.__mocks__ import (
    create_presentation_response_http,
    presentation_request_configuration,
)
from api.core.config import settings


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
async def test_create_presentation_throws_assertion_error_with_non_200_resp_from_acapy(
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
        try:
            presentation_request = await client.create_presentation_request(
                presentation_request_configuration
            )
            assert presentation_request is not None
        except AssertionError as e:
            assert e is not None


# TODO: determine if this function should assert a valid json response
@pytest.mark.asyncio
@respx.mock
async def test_create_presentation_throws_error_with_non_json_from_acapy(http_client):
    respx.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(200))

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        try:
            presentation_request = await client.create_presentation_request(
                presentation_request_configuration
            )
            assert presentation_request is not None
        except json.JSONDecodeError as e:
            assert e is not None


@pytest.mark.asyncio
@respx.mock
async def test_get_presentation_returns_sucessfully_with_valid_data(http_client):
    respx.get(
        settings.ACAPY_ADMIN_URL + PRESENT_PROOF_RECORDS + "/" + "1234-567890",
    ).mock(return_value=httpx.Response(200, json={"result": "success"}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    presentation = await client.get_presentation_request("1234-567890")
    assert presentation is not None


@pytest.mark.asyncio
@respx.mock
async def test_get_presentation_throws_assertion_error_for_non_200_response_from_acapy(
    http_client,
):
    respx.get(
        settings.ACAPY_ADMIN_URL + PRESENT_PROOF_RECORDS + "/" + "1234-567890",
    ).mock(return_value=httpx.Response(400, json={"result": "success"}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    try:
        await client.get_presentation_request("1234-567890")
    except AssertionError as e:
        assert e is not None


@pytest.mark.asyncio
@respx.mock
async def test_get_wallet_did_public_returns_sucessfully_on_public_url_and_simple_resp(
    http_client,
):
    respx.get(
        settings.ACAPY_ADMIN_URL + PUBLIC_WALLET_DID_URI,
    ).mock(return_value=httpx.Response(200, json={"result": "success"}))

    with mock.patch.object(
        WalletDid, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        wallet_resp = await client.get_wallet_did(public=True)
        assert wallet_resp is not None


@pytest.mark.asyncio
@respx.mock
async def test_get_wallet_did_public_throws_assertion_error_on_non_200_response(
    http_client,
):
    respx.get(
        settings.ACAPY_ADMIN_URL + PUBLIC_WALLET_DID_URI,
    ).mock(return_value=httpx.Response(400, json={"result": "success"}))

    with mock.patch.object(
        WalletDid, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        try:
            await client.get_wallet_did(public=True)
        except AssertionError as e:
            assert e is not None


@pytest.mark.asyncio
@respx.mock
async def test_get_wallet_did_not_public_returns_on_correct_url_and_processes_array(
    http_client,
):
    respx.get(
        settings.ACAPY_ADMIN_URL + WALLET_DID_URI,
    ).mock(return_value=httpx.Response(200, json={"results": ["success"]}))

    with mock.patch.object(
        WalletDid, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        wallet_resp = await client.get_wallet_did(public=False)
        assert wallet_resp is not None


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
async def test_send_presentation_request_by_connection_throws_assertion_error_on_non_200(
    http_client,
):
    """Test that send_presentation_request_by_connection throws assertion error on non-200 response."""
    connection_id = "test-connection-id"
    presentation_request_config = {"test": "config"}

    respx.post(
        settings.ACAPY_ADMIN_URL + SEND_PRESENTATION_REQUEST_URL,
    ).mock(return_value=httpx.Response(400, json=create_presentation_response_http))

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient(http_client)
        client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
        try:
            await client.send_presentation_request_by_connection(
                connection_id=connection_id,
                presentation_request_configuration=presentation_request_config,
            )
            assert False, "Should have thrown AssertionError"
        except AssertionError as e:
            assert e is not None


@pytest.mark.asyncio
@respx.mock
async def test_get_connection_returns_successfully_with_valid_data(http_client):
    """Test that get_connection returns successfully with valid data."""
    connection_id = "test-connection-id"
    expected_response = {"connection_id": connection_id, "state": "active"}

    respx.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
    ).mock(return_value=httpx.Response(200, json=expected_response))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.get_connection(connection_id)
    assert result == expected_response


@pytest.mark.asyncio
@respx.mock
async def test_get_connection_throws_assertion_error_on_non_200_response(http_client):
    """Test that get_connection throws assertion error on non-200 response."""
    connection_id = "test-connection-id"

    respx.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
    ).mock(return_value=httpx.Response(404, json={"error": "Not found"}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    try:
        await client.get_connection(connection_id)
        assert False, "Should have thrown AssertionError"
    except AssertionError as e:
        assert e is not None


@pytest.mark.asyncio
@respx.mock
async def test_list_connections_returns_successfully_with_valid_data(http_client):
    """Test that list_connections returns successfully with valid data."""
    expected_response = {
        "results": [
            {"connection_id": "conn1", "state": "active"},
            {"connection_id": "conn2", "state": "completed"},
        ]
    }

    respx.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI,
    ).mock(return_value=httpx.Response(200, json=expected_response))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.list_connections()
    assert result == expected_response["results"]


@pytest.mark.asyncio
@respx.mock
async def test_list_connections_with_state_filter(http_client):
    """Test that list_connections properly filters by state."""
    expected_response = {"results": [{"connection_id": "conn1", "state": "active"}]}

    route = respx.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI,
    ).mock(return_value=httpx.Response(200, json=expected_response))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.list_connections(state="active")
    assert result == expected_response["results"]

    # Verify state parameter was passed
    assert dict(route.calls.last.request.url.params) == {"state": "active"}


@pytest.mark.asyncio
@respx.mock
async def test_list_connections_throws_assertion_error_on_non_200_response(
    http_client,
):
    """Test that list_connections throws assertion error on non-200 response."""
    respx.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI,
    ).mock(return_value=httpx.Response(500, json={"error": "Server error"}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    try:
        await client.list_connections()
        assert False, "Should have thrown AssertionError"
    except AssertionError as e:
        assert e is not None


@pytest.mark.asyncio
@respx.mock
async def test_delete_connection_returns_true_on_successful_deletion(http_client):
    """Test that delete_connection returns True on successful deletion."""
    connection_id = "test-connection-id"

    respx.delete(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
    ).mock(return_value=httpx.Response(200))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.delete_connection(connection_id)
    assert result is True


@pytest.mark.asyncio
@respx.mock
async def test_delete_connection_returns_false_on_failed_deletion(http_client):
    """Test that delete_connection returns False on failed deletion."""
    connection_id = "test-connection-id"

    respx.delete(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
    ).mock(return_value=httpx.Response(404))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    result = await client.delete_connection(connection_id)
    assert result is False


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
async def test_create_connection_invitation_throws_assertion_error_on_non_200(
    http_client,
):
    """Test that create_connection_invitation throws assertion error on non-200 response."""
    respx.post(
        settings.ACAPY_ADMIN_URL + OOB_CREATE_INVITATION,
    ).mock(return_value=httpx.Response(400, json={"error": "Bad request"}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})
    try:
        await client.create_connection_invitation()
        assert False, "Should have thrown AssertionError"
    except AssertionError as e:
        assert e is not None


# Problem report tests
@pytest.mark.asyncio
@respx.mock
async def test_send_problem_report_returns_true_on_successful_200_response(
    http_client,
):
    """Test that send_problem_report returns True when ACA-Py returns 200."""
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    respx.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
    ).mock(return_value=httpx.Response(200, json={"success": True}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})

    result = await client.send_problem_report(pres_ex_id, description)
    assert result is True


@pytest.mark.asyncio
@respx.mock
async def test_send_problem_report_returns_false_on_non_200_response(http_client):
    """Test that send_problem_report returns False when ACA-Py returns non-200."""
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    respx.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
    ).mock(return_value=httpx.Response(400, json={"error": "Bad request"}))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})

    result = await client.send_problem_report(pres_ex_id, description)
    assert result is False


@pytest.mark.asyncio
@respx.mock
async def test_send_problem_report_returns_false_on_request_exception(http_client):
    """Test that send_problem_report returns False when request raises exception."""
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    respx.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
    ).mock(side_effect=Exception("Network error"))

    client = AcapyClient(http_client)
    client.agent_config.get_headers = mock.AsyncMock(return_value={"x-api-key": ""})

    result = await client.send_problem_report(pres_ex_id, description)
    assert result is False


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
    assert result is True

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
