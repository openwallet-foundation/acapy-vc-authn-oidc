import json

import mock
import pytest
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
from api.core.acapy.config import MultiTenantAcapy, SingleTenantAcapy
from api.core.acapy.models import CreatePresentationResponse, WalletDid
from api.core.acapy.tests.__mocks__ import (
    create_presentation_response_http,
    presentation_request_configuration,
)
from api.core.config import settings


@pytest.mark.asyncio
@mock.patch.object(settings, "ACAPY_TENANCY", None)
async def test_init_no_setting_returns_client_with_single_tenancy_config():
    client = AcapyClient()
    assert client is not None
    assert isinstance(client.agent_config, SingleTenantAcapy) is True


@pytest.mark.asyncio
@mock.patch.object(settings, "ACAPY_TENANCY", "single")
async def test_init_single_returns_client_with_single_tenancy_config():
    client = AcapyClient()
    assert client is not None
    assert isinstance(client.agent_config, SingleTenantAcapy) is True


@pytest.mark.asyncio
@mock.patch.object(settings, "ACAPY_TENANCY", "multi")
async def test_init_multi_returns_client_with_multi_tenancy_config():
    client = AcapyClient()
    assert client is not None
    assert isinstance(client.agent_config, MultiTenantAcapy) is True


@pytest.mark.asyncio
async def test_create_presentation_returns_sucessfully_with_valid_data(requests_mock):
    requests_mock.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
        headers={},
        json=json.dumps(create_presentation_response_http),
        status_code=200,
    )

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient()
        client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
        presentation_request = client.create_presentation_request(
            presentation_request_configuration
        )
        assert presentation_request is not None


@pytest.mark.asyncio
async def test_create_presentation_throws_assertion_error_with_non_200_resp_from_acapy(
    requests_mock,
):
    requests_mock.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
        headers={},
        json=json.dumps(create_presentation_response_http),
        status_code=400,
    )

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient()
        client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
        try:
            presentation_request = client.create_presentation_request(
                presentation_request_configuration
            )
            assert presentation_request is not None
        except AssertionError as e:
            assert e is not None


# TODO: determine if this function should assert a valid json response
@pytest.mark.asyncio
async def test_create_presentation_throws_error_with_non_json_from_acapy(requests_mock):
    requests_mock.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
        headers={},
        status_code=200,
    )

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient()
        client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
        try:
            presentation_request = client.create_presentation_request(
                presentation_request_configuration
            )
            assert presentation_request is not None
        except json.JSONDecodeError as e:
            assert e is not None


@pytest.mark.asyncio
async def test_get_presentation_returns_sucessfully_with_valid_data(requests_mock):
    requests_mock.get(
        settings.ACAPY_ADMIN_URL + PRESENT_PROOF_RECORDS + "/" + "1234-567890",
        headers={},
        json={"result": "success"},
        status_code=200,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    presentation = client.get_presentation_request("1234-567890")
    assert presentation is not None


@pytest.mark.asyncio
async def test_get_presentation_throws_assertion_error_for_non_200_response_from_acapy(
    requests_mock,
):
    requests_mock.get(
        settings.ACAPY_ADMIN_URL + PRESENT_PROOF_RECORDS + "/" + "1234-567890",
        headers={},
        json={"result": "success"},
        status_code=400,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    try:
        client.get_presentation_request("1234-567890")
    except AssertionError as e:
        assert e is not None


@pytest.mark.asyncio
async def test_get_wallet_did_public_returns_sucessfully_on_public_url_and_simple_resp(
    requests_mock,
):
    requests_mock.get(
        settings.ACAPY_ADMIN_URL + PUBLIC_WALLET_DID_URI,
        headers={},
        json={"result": "success"},
        status_code=200,
    )
    with mock.patch.object(
        WalletDid, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient()
        client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
        wallet_resp = client.get_wallet_did(public=True)
        assert wallet_resp is not None


@pytest.mark.asyncio
async def test_get_wallet_did_public_throws_assertion_error_on_non_200_response(
    requests_mock,
):
    requests_mock.get(
        settings.ACAPY_ADMIN_URL + PUBLIC_WALLET_DID_URI,
        headers={},
        json={"result": "success"},
        status_code=400,
    )
    with mock.patch.object(
        WalletDid, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient()
        client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
        try:
            client.get_wallet_did(public=True)
        except AssertionError as e:
            assert e is not None


@pytest.mark.asyncio
async def test_get_wallet_did_not_public_returns_on_correct_url_and_processes_array(
    requests_mock,
):
    requests_mock.get(
        settings.ACAPY_ADMIN_URL + WALLET_DID_URI,
        headers={},
        json={"results": ["success"]},
        status_code=200,
    )
    with mock.patch.object(
        WalletDid, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient()
        client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
        wallet_resp = client.get_wallet_did(public=False)
        assert wallet_resp is not None


# Connection-based verification tests
@pytest.mark.asyncio
async def test_send_presentation_request_by_connection_returns_successfully(
    requests_mock,
):
    """Test that send_presentation_request_by_connection returns successfully with valid data."""
    connection_id = "test-connection-id"
    presentation_request_config = {"test": "config"}

    requests_mock.post(
        settings.ACAPY_ADMIN_URL + SEND_PRESENTATION_REQUEST_URL,
        headers={},
        json=json.dumps(create_presentation_response_http),
        status_code=200,
    )

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient()
        client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
        result = client.send_presentation_request_by_connection(
            connection_id=connection_id,
            presentation_request_configuration=presentation_request_config,
        )
        assert result is not None


@pytest.mark.asyncio
async def test_send_presentation_request_by_connection_throws_assertion_error_on_non_200(
    requests_mock,
):
    """Test that send_presentation_request_by_connection throws assertion error on non-200 response."""
    connection_id = "test-connection-id"
    presentation_request_config = {"test": "config"}

    requests_mock.post(
        settings.ACAPY_ADMIN_URL + SEND_PRESENTATION_REQUEST_URL,
        headers={},
        json=json.dumps(create_presentation_response_http),
        status_code=400,
    )

    with mock.patch.object(
        CreatePresentationResponse, "model_validate", return_value={"result": "success"}
    ):
        client = AcapyClient()
        client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
        try:
            client.send_presentation_request_by_connection(
                connection_id=connection_id,
                presentation_request_configuration=presentation_request_config,
            )
            assert False, "Should have thrown AssertionError"
        except AssertionError as e:
            assert e is not None


@pytest.mark.asyncio
async def test_get_connection_returns_successfully_with_valid_data(requests_mock):
    """Test that get_connection returns successfully with valid data."""
    connection_id = "test-connection-id"
    expected_response = {"connection_id": connection_id, "state": "active"}

    requests_mock.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
        headers={},
        json=expected_response,
        status_code=200,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    result = client.get_connection(connection_id)
    assert result == expected_response


@pytest.mark.asyncio
async def test_get_connection_throws_assertion_error_on_non_200_response(requests_mock):
    """Test that get_connection throws assertion error on non-200 response."""
    connection_id = "test-connection-id"

    requests_mock.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
        headers={},
        json={"error": "Not found"},
        status_code=404,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    try:
        client.get_connection(connection_id)
        assert False, "Should have thrown AssertionError"
    except AssertionError as e:
        assert e is not None


@pytest.mark.asyncio
async def test_list_connections_returns_successfully_with_valid_data(requests_mock):
    """Test that list_connections returns successfully with valid data."""
    expected_response = {
        "results": [
            {"connection_id": "conn1", "state": "active"},
            {"connection_id": "conn2", "state": "completed"},
        ]
    }

    requests_mock.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI,
        headers={},
        json=expected_response,
        status_code=200,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    result = client.list_connections()
    assert result == expected_response["results"]


@pytest.mark.asyncio
async def test_list_connections_with_state_filter(requests_mock):
    """Test that list_connections properly filters by state."""
    expected_response = {"results": [{"connection_id": "conn1", "state": "active"}]}

    requests_mock.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI,
        headers={},
        json=expected_response,
        status_code=200,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    result = client.list_connections(state="active")
    assert result == expected_response["results"]

    # Verify state parameter was passed
    assert requests_mock.last_request.qs == {"state": ["active"]}


@pytest.mark.asyncio
async def test_list_connections_throws_assertion_error_on_non_200_response(
    requests_mock,
):
    """Test that list_connections throws assertion error on non-200 response."""
    requests_mock.get(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI,
        headers={},
        json={"error": "Server error"},
        status_code=500,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    try:
        client.list_connections()
        assert False, "Should have thrown AssertionError"
    except AssertionError as e:
        assert e is not None


@pytest.mark.asyncio
async def test_delete_connection_returns_true_on_successful_deletion(requests_mock):
    """Test that delete_connection returns True on successful deletion."""
    connection_id = "test-connection-id"

    requests_mock.delete(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
        headers={},
        status_code=200,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    result = client.delete_connection(connection_id)
    assert result is True


@pytest.mark.asyncio
async def test_delete_connection_returns_false_on_failed_deletion(requests_mock):
    """Test that delete_connection returns False on failed deletion."""
    connection_id = "test-connection-id"

    requests_mock.delete(
        settings.ACAPY_ADMIN_URL + CONNECTIONS_URI + "/" + connection_id,
        headers={},
        status_code=404,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    result = client.delete_connection(connection_id)
    assert result is False


@pytest.mark.asyncio
async def test_create_connection_invitation_ephemeral_returns_successfully(
    requests_mock,
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

    requests_mock.post(
        settings.ACAPY_ADMIN_URL + OOB_CREATE_INVITATION,
        headers={},
        json=expected_response,
        status_code=200,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    result = client.create_connection_invitation(multi_use=False)
    assert result is not None

    # Verify the request payload for ephemeral connection
    request_payload = requests_mock.last_request.json()
    assert "handshake_protocols" in request_payload
    assert "goal_code" in request_payload
    assert request_payload["goal_code"] == "aries.vc.verify.once"


@pytest.mark.asyncio
async def test_create_connection_invitation_persistent_returns_successfully(
    requests_mock,
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

    requests_mock.post(
        settings.ACAPY_ADMIN_URL + OOB_CREATE_INVITATION,
        headers={},
        json=expected_response,
        status_code=200,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    result = client.create_connection_invitation(multi_use=True)
    assert result is not None

    # Verify the request payload for persistent connection
    request_payload = requests_mock.last_request.json()
    assert "handshake_protocols" in request_payload
    assert "goal_code" in request_payload
    assert request_payload["goal_code"] == "aries.vc.verify"


@pytest.mark.asyncio
async def test_create_connection_invitation_throws_assertion_error_on_non_200(
    requests_mock,
):
    """Test that create_connection_invitation throws assertion error on non-200 response."""
    requests_mock.post(
        settings.ACAPY_ADMIN_URL + OOB_CREATE_INVITATION,
        headers={},
        json={"error": "Bad request"},
        status_code=400,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
    try:
        client.create_connection_invitation()
        assert False, "Should have thrown AssertionError"
    except AssertionError as e:
        assert e is not None


# Problem report tests
@pytest.mark.asyncio
async def test_send_problem_report_returns_true_on_successful_200_response(
    requests_mock,
):
    """Test that send_problem_report returns True when ACA-Py returns 200."""
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    requests_mock.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
        headers={},
        json={"success": True},
        status_code=200,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})

    result = client.send_problem_report(pres_ex_id, description)
    assert result is True


@pytest.mark.asyncio
async def test_send_problem_report_returns_false_on_non_200_response(requests_mock):
    """Test that send_problem_report returns False when ACA-Py returns non-200."""
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    requests_mock.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
        headers={},
        json={"error": "Bad request"},
        status_code=400,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})

    result = client.send_problem_report(pres_ex_id, description)
    assert result is False


@pytest.mark.asyncio
async def test_send_problem_report_returns_false_on_request_exception(requests_mock):
    """Test that send_problem_report returns False when request raises exception."""
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    # Mock requests.post to raise an exception
    requests_mock.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
        exc=Exception("Network error"),
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})

    result = client.send_problem_report(pres_ex_id, description)
    assert result is False


@pytest.mark.asyncio
async def test_send_problem_report_sends_correct_payload(requests_mock):
    """Test that send_problem_report sends the correct payload to ACA-Py."""
    pres_ex_id = "test-pres-ex-id"
    description = "Test problem description"

    requests_mock.post(
        settings.ACAPY_ADMIN_URL
        + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
        headers={},
        json={"success": True},
        status_code=200,
    )

    client = AcapyClient()
    client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})

    result = client.send_problem_report(pres_ex_id, description)
    assert result is True

    # Verify the request was made with correct parameters
    assert requests_mock.last_request.json() == {"description": description}
    assert requests_mock.call_count == 1

@pytest.mark.asyncio
async def test_create_presentation_request_uses_configured_proof_format(requests_mock):
    # Verify payload key respects ACAPY_PROOF_FORMAT
    requests_mock.post(
        settings.ACAPY_ADMIN_URL + CREATE_PRESENTATION_REQUEST_URL,
        headers={},
        json=json.dumps(create_presentation_response_http),
        status_code=200,
    )

    # Patch the setting to 'anoncreds'
    with mock.patch.object(settings, "ACAPY_PROOF_FORMAT", "anoncreds"):
        with mock.patch.object(
            CreatePresentationResponse, "model_validate", return_value={"result": "success"}
        ):
            client = AcapyClient()
            client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
            
            client.create_presentation_request(presentation_request_configuration)
            
            # Inspect the actual JSON body sent to ACA-Py
            request_json = requests_mock.last_request.json()
            assert "anoncreds" in request_json["presentation_request"]
            assert "indy" not in request_json["presentation_request"]

@pytest.mark.asyncio
async def test_send_presentation_request_by_connection_uses_configured_proof_format(requests_mock):
    # Verify connection-based request also respects ACAPY_PROOF_FORMAT
    requests_mock.post(
        settings.ACAPY_ADMIN_URL + SEND_PRESENTATION_REQUEST_URL,
        headers={},
        json=json.dumps(create_presentation_response_http),
        status_code=200,
    )

    with mock.patch.object(settings, "ACAPY_PROOF_FORMAT", "anoncreds"):
        with mock.patch.object(
            CreatePresentationResponse, "model_validate", return_value={"result": "success"}
        ):
            client = AcapyClient()
            client.agent_config.get_headers = mock.MagicMock(return_value={"x-api-key": ""})
            
            client.send_presentation_request_by_connection("conn_id", presentation_request_configuration)
            
            request_json = requests_mock.last_request.json()
            assert "anoncreds" in request_json["presentation_request"]
            assert "indy" not in request_json["presentation_request"]