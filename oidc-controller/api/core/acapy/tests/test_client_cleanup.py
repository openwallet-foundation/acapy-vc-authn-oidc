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
