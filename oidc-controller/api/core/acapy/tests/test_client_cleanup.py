"""Tests for AcapyClient cleanup-related methods."""

from uuid import UUID

import httpx
import pytest
import respx
from api.core.acapy.client import AcapyClient
from api.core.config import settings


@pytest.fixture
def http_client():
    return httpx.AsyncClient()


@pytest.fixture
def acapy_client(http_client):
    return AcapyClient(http_client)


BASE_URL = settings.ACAPY_ADMIN_URL


class TestAcapyClientCleanup:
    """Test cleanup-related methods in AcapyClient."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_presentation_record_success(self, acapy_client):
        pres_ex_id = "test-pres-ex-id"
        respx.delete(f"{BASE_URL}/present-proof-2.0/records/{pres_ex_id}").mock(
            return_value=httpx.Response(200)
        )

        result = await acapy_client.delete_presentation_record(pres_ex_id)

        assert result is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_presentation_record_failure(self, acapy_client):
        pres_ex_id = "test-pres-ex-id"
        respx.delete(f"{BASE_URL}/present-proof-2.0/records/{pres_ex_id}").mock(
            return_value=httpx.Response(404, content=b"Record not found")
        )

        result = await acapy_client.delete_presentation_record(pres_ex_id)

        assert result is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_presentation_record_exception(self, acapy_client):
        pres_ex_id = "test-pres-ex-id"
        respx.delete(f"{BASE_URL}/present-proof-2.0/records/{pres_ex_id}").mock(
            side_effect=httpx.ConnectError("Network error")
        )

        result = await acapy_client.delete_presentation_record(pres_ex_id)

        assert result is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_presentation_record_with_uuid(self, acapy_client):
        pres_ex_id = UUID("12345678-1234-5678-1234-567812345678")
        respx.delete(f"{BASE_URL}/present-proof-2.0/records/{pres_ex_id}").mock(
            return_value=httpx.Response(200)
        )

        result = await acapy_client.delete_presentation_record(pres_ex_id)

        assert result is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_presentation_records_page_success(self, acapy_client):
        mock_records = [
            {"pres_ex_id": "record-1", "created_at": "2024-01-01T12:00:00Z"},
            {"pres_ex_id": "record-2", "created_at": "2024-01-02T12:00:00Z"},
        ]
        route = respx.get(f"{BASE_URL}/present-proof-2.0/records").mock(
            return_value=httpx.Response(200, json={"results": mock_records})
        )

        result = await acapy_client.get_presentation_records_page(limit=50, offset=10)

        assert [r["pres_ex_id"] for r in result] == ["record-1", "record-2"]
        params = route.calls[0].request.url.params
        assert params["limit"] == "50"
        assert params["offset"] == "10"
        assert params["role"] == "verifier"

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_presentation_records_page_missing_results_key(
        self, acapy_client
    ):
        respx.get(f"{BASE_URL}/present-proof-2.0/records").mock(
            return_value=httpx.Response(200, json={"data": []})
        )

        assert await acapy_client.get_presentation_records_page(limit=10) == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_presentation_records_page_http_error_raises(self, acapy_client):
        respx.get(f"{BASE_URL}/present-proof-2.0/records").mock(
            return_value=httpx.Response(500, content=b"Internal server error")
        )

        with pytest.raises(httpx.HTTPStatusError):
            await acapy_client.get_presentation_records_page(limit=10)

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_presentation_records_page_network_error_raises(
        self, acapy_client
    ):
        respx.get(f"{BASE_URL}/present-proof-2.0/records").mock(
            side_effect=httpx.ConnectError("Network error")
        )

        with pytest.raises(httpx.ConnectError):
            await acapy_client.get_presentation_records_page(limit=10)

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_presentation_record_and_connection_both_success(
        self, acapy_client
    ):
        pres_ex_id = "test-pres-ex-id"
        connection_id = "test-connection-id"
        respx.delete(f"{BASE_URL}/present-proof-2.0/records/{pres_ex_id}").mock(
            return_value=httpx.Response(200)
        )
        respx.delete(f"{BASE_URL}/connections/{connection_id}").mock(
            return_value=httpx.Response(200)
        )

        (
            presentation_deleted,
            connection_deleted,
            errors,
        ) = await acapy_client.delete_presentation_record_and_connection(
            pres_ex_id, connection_id
        )

        assert presentation_deleted is True
        assert connection_deleted is True
        assert errors == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_presentation_record_and_connection_presentation_only(
        self, acapy_client
    ):
        pres_ex_id = "test-pres-ex-id"
        respx.delete(f"{BASE_URL}/present-proof-2.0/records/{pres_ex_id}").mock(
            return_value=httpx.Response(200)
        )

        (
            presentation_deleted,
            connection_deleted,
            errors,
        ) = await acapy_client.delete_presentation_record_and_connection(
            pres_ex_id, None
        )

        assert presentation_deleted is True
        assert connection_deleted is False
        assert errors == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_presentation_record_and_connection_mixed_results(
        self, acapy_client
    ):
        pres_ex_id = "test-pres-ex-id"
        connection_id = "test-connection-id"
        respx.delete(f"{BASE_URL}/present-proof-2.0/records/{pres_ex_id}").mock(
            return_value=httpx.Response(200)
        )
        respx.delete(f"{BASE_URL}/connections/{connection_id}").mock(
            return_value=httpx.Response(404)
        )

        (
            presentation_deleted,
            connection_deleted,
            errors,
        ) = await acapy_client.delete_presentation_record_and_connection(
            pres_ex_id, connection_id
        )

        assert presentation_deleted is True
        assert connection_deleted is False
        assert len(errors) == 1
        assert "Failed to delete connection" in errors[0]

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_presentation_record_and_connection_both_fail(
        self, acapy_client
    ):
        pres_ex_id = "test-pres-ex-id"
        connection_id = "test-connection-id"
        respx.delete(f"{BASE_URL}/present-proof-2.0/records/{pres_ex_id}").mock(
            return_value=httpx.Response(404)
        )
        respx.delete(f"{BASE_URL}/connections/{connection_id}").mock(
            return_value=httpx.Response(404)
        )

        (
            presentation_deleted,
            connection_deleted,
            errors,
        ) = await acapy_client.delete_presentation_record_and_connection(
            pres_ex_id, connection_id
        )

        assert presentation_deleted is False
        assert connection_deleted is False
        assert len(errors) == 2

    @pytest.mark.asyncio
    async def test_delete_presentation_record_and_connection_no_ids(self, acapy_client):
        (
            presentation_deleted,
            connection_deleted,
            errors,
        ) = await acapy_client.delete_presentation_record_and_connection(None, None)

        assert presentation_deleted is False
        assert connection_deleted is False
        assert errors == []


class TestDeleteConnection:
    """Tests for delete_connection, including missing network-error coverage."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_connection_network_error_returns_false(self, acapy_client):
        """delete_connection catches ConnectError and returns False."""
        respx.delete(f"{BASE_URL}/connections/conn-1").mock(
            side_effect=httpx.ConnectError("ACA-Py unreachable")
        )

        result = await acapy_client.delete_connection("conn-1")

        assert result is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_connection_timeout_returns_false(self, acapy_client):
        """delete_connection catches ReadTimeout and returns False."""
        respx.delete(f"{BASE_URL}/connections/conn-1").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )

        result = await acapy_client.delete_connection("conn-1")

        assert result is False


class TestPagedListing:
    """Tests for the paged connection and OOB record listing methods."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_connections_page_sends_no_state_filter(self, acapy_client):
        connections = [{"connection_id": "conn-0"}]
        route = respx.get(f"{BASE_URL}/connections").mock(
            return_value=httpx.Response(200, json={"results": connections})
        )

        result = await acapy_client.get_connections_page(limit=100, offset=200)

        assert result == connections
        params = route.calls[0].request.url.params
        assert params["limit"] == "100"
        assert params["offset"] == "200"
        assert "state" not in params

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_connections_page_http_error_raises(self, acapy_client):
        respx.get(f"{BASE_URL}/connections").mock(
            return_value=httpx.Response(500, content=b"Internal Server Error")
        )

        with pytest.raises(httpx.HTTPStatusError):
            await acapy_client.get_connections_page(limit=100)

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_oob_records_page_filters_sender_role(self, acapy_client):
        records = [{"invi_msg_id": "invi-1", "state": "await-response"}]
        route = respx.get(f"{BASE_URL}/out-of-band/records").mock(
            return_value=httpx.Response(200, json={"results": records})
        )

        result = await acapy_client.get_oob_records_page(limit=100)

        assert result == records
        params = route.calls[0].request.url.params
        assert params["role"] == "sender"
        assert params["offset"] == "0"


class TestDeleteOobInvitation:
    """Tests for delete_oob_invitation."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_success(self, acapy_client):
        respx.delete(f"{BASE_URL}/out-of-band/invitations/invi-1").mock(
            return_value=httpx.Response(200, json={})
        )

        assert await acapy_client.delete_oob_invitation("invi-1") is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_already_gone_counts_as_success(self, acapy_client):
        respx.delete(f"{BASE_URL}/out-of-band/invitations/invi-1").mock(
            return_value=httpx.Response(404)
        )

        assert await acapy_client.delete_oob_invitation("invi-1") is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_server_error_returns_false(self, acapy_client):
        respx.delete(f"{BASE_URL}/out-of-band/invitations/invi-1").mock(
            return_value=httpx.Response(500)
        )

        assert await acapy_client.delete_oob_invitation("invi-1") is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error_returns_false(self, acapy_client):
        respx.delete(f"{BASE_URL}/out-of-band/invitations/invi-1").mock(
            side_effect=httpx.ConnectError("ACA-Py unreachable")
        )

        assert await acapy_client.delete_oob_invitation("invi-1") is False


class TestTimeoutBehaviour:
    """Documents how AcapyClient methods behave when httpx raises a timeout.

    Methods that use assert-on-status (create_presentation_request, get_wallet_did,
    create_connection_invitation, get_presentation_request) have no internal
    exception handling, so timeouts propagate to the caller unchanged.
    Methods with explicit try/except (delete_connection, delete_presentation_record,
    send_problem_report) swallow the error and return a safe default.
    """

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_connection_timeout_returns_false(self, acapy_client):
        respx.delete(f"{BASE_URL}/connections/conn-1").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )
        assert await acapy_client.delete_connection("conn-1") is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete_presentation_record_timeout_returns_false(self, acapy_client):
        respx.delete(f"{BASE_URL}/present-proof-2.0/records/rec-1").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )
        assert await acapy_client.delete_presentation_record("rec-1") is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_send_problem_report_timeout_returns_false(self, acapy_client):
        respx.post(f"{BASE_URL}/present-proof-2.0/records/rec-1/problem-report").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )
        assert await acapy_client.send_problem_report("rec-1", "desc") is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_create_presentation_request_timeout_propagates(self, acapy_client):
        """Methods without try/except let timeouts surface — callers must handle them."""
        respx.post(f"{BASE_URL}/present-proof-2.0/create-request").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )
        with pytest.raises(httpx.ReadTimeout):
            await acapy_client.create_presentation_request({})
