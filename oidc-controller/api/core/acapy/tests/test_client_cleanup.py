"""Tests for AcapyClient cleanup-related methods."""

import pytest
import httpx
import respx
from uuid import UUID

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
    async def test_get_all_presentation_records_success(self, acapy_client):
        mock_records = [
            {
                "pres_ex_id": "record-1",
                "created_at": "2024-01-01T12:00:00Z",
                "state": "done",
            },
            {
                "pres_ex_id": "record-2",
                "created_at": "2024-01-02T12:00:00Z",
                "state": "done",
            },
        ]
        respx.get(f"{BASE_URL}/present-proof-2.0/records").mock(
            return_value=httpx.Response(200, json={"results": mock_records})
        )

        result = await acapy_client.get_all_presentation_records()

        assert len(result) == 2
        assert result[0]["pres_ex_id"] == "record-1"
        assert result[1]["pres_ex_id"] == "record-2"

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_all_presentation_records_empty_results(self, acapy_client):
        respx.get(f"{BASE_URL}/present-proof-2.0/records").mock(
            return_value=httpx.Response(200, json={"results": []})
        )

        result = await acapy_client.get_all_presentation_records()

        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_all_presentation_records_missing_results_key(self, acapy_client):
        respx.get(f"{BASE_URL}/present-proof-2.0/records").mock(
            return_value=httpx.Response(200, json={"data": []})
        )

        result = await acapy_client.get_all_presentation_records()

        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_all_presentation_records_http_error(self, acapy_client):
        respx.get(f"{BASE_URL}/present-proof-2.0/records").mock(
            return_value=httpx.Response(500, content=b"Internal server error")
        )

        result = await acapy_client.get_all_presentation_records()

        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_all_presentation_records_network_exception(self, acapy_client):
        respx.get(f"{BASE_URL}/present-proof-2.0/records").mock(
            side_effect=httpx.ConnectError("Network error")
        )

        result = await acapy_client.get_all_presentation_records()

        assert result == []

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

        presentation_deleted, connection_deleted, errors = (
            await acapy_client.delete_presentation_record_and_connection(
                pres_ex_id, connection_id
            )
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

        presentation_deleted, connection_deleted, errors = (
            await acapy_client.delete_presentation_record_and_connection(
                pres_ex_id, None
            )
        )

        assert presentation_deleted is True
        assert connection_deleted is None
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

        presentation_deleted, connection_deleted, errors = (
            await acapy_client.delete_presentation_record_and_connection(
                pres_ex_id, connection_id
            )
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

        presentation_deleted, connection_deleted, errors = (
            await acapy_client.delete_presentation_record_and_connection(
                pres_ex_id, connection_id
            )
        )

        assert presentation_deleted is False
        assert connection_deleted is False
        assert len(errors) == 2

    @pytest.mark.asyncio
    async def test_delete_presentation_record_and_connection_no_ids(self, acapy_client):
        presentation_deleted, connection_deleted, errors = (
            await acapy_client.delete_presentation_record_and_connection(None, None)
        )

        assert presentation_deleted is False
        assert connection_deleted is None
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


class TestGetConnectionsBatched:
    """Tests for the get_connections_batched async generator."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_results_yields_nothing(self, acapy_client):
        """When ACA-Py returns no connections the generator yields nothing."""
        respx.get(f"{BASE_URL}/connections").mock(
            return_value=httpx.Response(200, json={"results": []})
        )

        batches = [batch async for batch in acapy_client.get_connections_batched()]

        assert batches == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_single_partial_batch_yields_once(self, acapy_client):
        """A single page smaller than batch_size yields once and stops without fetching another page."""
        connections = [{"connection_id": f"conn-{i}"} for i in range(3)]
        route = respx.get(f"{BASE_URL}/connections").mock(
            return_value=httpx.Response(200, json={"results": connections})
        )

        batches = [
            batch async for batch in acapy_client.get_connections_batched(batch_size=10)
        ]

        assert len(batches) == 1
        assert batches[0] == connections
        assert route.call_count == 1  # No extra page fetch

    @respx.mock
    @pytest.mark.asyncio
    async def test_multiple_pages_fetches_until_partial_page(self, acapy_client):
        """When the first page is exactly batch_size, a second page is fetched.
        Pagination stops when the second page is partial (< batch_size).
        """
        page1 = [{"connection_id": f"conn-{i}"} for i in range(3)]
        page2 = [{"connection_id": f"conn-{i}"} for i in range(3, 5)]

        call_count = 0

        def paginated_response(request):
            nonlocal call_count
            call_count += 1
            offset = int(request.url.params.get("offset", 0))
            if offset == 0:
                return httpx.Response(200, json={"results": page1})
            return httpx.Response(200, json={"results": page2})

        respx.get(f"{BASE_URL}/connections").mock(side_effect=paginated_response)

        batches = [
            batch async for batch in acapy_client.get_connections_batched(batch_size=3)
        ]

        assert len(batches) == 2
        assert batches[0] == page1
        assert batches[1] == page2
        assert call_count == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_full_last_page_triggers_extra_fetch_then_stops(self, acapy_client):
        """When the last page is exactly batch_size the generator fetches one more page.
        An empty response on that extra fetch terminates the loop correctly.
        """
        page1 = [{"connection_id": f"conn-{i}"} for i in range(2)]
        call_count = 0

        def paginated_response(request):
            nonlocal call_count
            call_count += 1
            offset = int(request.url.params.get("offset", 0))
            if offset == 0:
                return httpx.Response(200, json={"results": page1})
            return httpx.Response(200, json={"results": []})  # empty follow-up

        respx.get(f"{BASE_URL}/connections").mock(side_effect=paginated_response)

        batches = [
            batch async for batch in acapy_client.get_connections_batched(batch_size=2)
        ]

        assert len(batches) == 1
        assert batches[0] == page1
        assert call_count == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error_stops_iteration_gracefully(self, acapy_client):
        """A ConnectError on the first page causes the generator to yield nothing
        (since _get_connections_page returns [] on exception → loop breaks).
        """
        respx.get(f"{BASE_URL}/connections").mock(
            side_effect=httpx.ConnectError("ACA-Py unreachable")
        )

        batches = [batch async for batch in acapy_client.get_connections_batched()]

        assert batches == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_error_on_page_stops_iteration(self, acapy_client):
        """A non-200 response on any page causes _get_connections_page to return []
        which breaks the loop.
        """
        respx.get(f"{BASE_URL}/connections").mock(
            return_value=httpx.Response(500, content=b"Internal Server Error")
        )

        batches = [batch async for batch in acapy_client.get_connections_batched()]

        assert batches == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_correct_pagination_params_sent(self, acapy_client):
        """Verifies that limit, offset, and state query params are sent correctly."""
        page1 = [{"connection_id": "conn-0"}, {"connection_id": "conn-1"}]
        page2 = [{"connection_id": "conn-2"}]

        call_num = 0

        def paginated_response(request):
            nonlocal call_num
            call_num += 1
            offset = int(request.url.params.get("offset", 0))
            if offset == 0:
                return httpx.Response(200, json={"results": page1})
            return httpx.Response(200, json={"results": page2})

        route = respx.get(f"{BASE_URL}/connections").mock(
            side_effect=paginated_response
        )

        batches = [
            batch
            async for batch in acapy_client.get_connections_batched(
                state="invitation", batch_size=2
            )
        ]

        assert len(batches) == 2
        first_req = route.calls[0].request
        assert first_req.url.params["limit"] == "2"
        assert first_req.url.params["offset"] == "0"
        assert first_req.url.params["state"] == "invitation"

        second_req = route.calls[1].request
        assert second_req.url.params["offset"] == "2"


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
        respx.post(
            f"{BASE_URL}/present-proof-2.0/records/rec-1/problem-report"
        ).mock(side_effect=httpx.ReadTimeout("timed out"))
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
