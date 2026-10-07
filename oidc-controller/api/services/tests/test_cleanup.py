"""Tests for the ACA-Py record cleanup service."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from api.services import cleanup as cleanup_module
from api.services.cleanup import (
    MAX_REPORTED_ERRORS,
    PAGE_SIZE,
    _parse_record_timestamp,
    perform_cleanup,
    validate_cleanup_configuration,
)

RETENTION_HOURS = 24
EXPIRE_SECONDS = 300


def make_settings(**overrides):
    values = {
        "CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS": RETENTION_HOURS,
        "CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS": 1000,
        "CONTROLLER_CLEANUP_MAX_CONNECTIONS": 2000,
        "CONTROLLER_CLEANUP_CONCURRENCY": 5,
        "CONTROLLER_CLEANUP_MAX_DURATION_SECONDS": 240,
        "CONTROLLER_PRESENTATION_EXPIRE_TIME": EXPIRE_SECONDS,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def ts(**delta) -> str:
    return (datetime.now(UTC) - timedelta(**delta)).isoformat().replace("+00:00", "Z")


OLD = {"hours": RETENTION_HOURS + 1}
RECENT = {"hours": 1}
EXPIRED = {"seconds": EXPIRE_SECONDS + 60}
FRESH = {"seconds": 10}


def pres(pres_ex_id, age, state="request-sent"):
    return {"pres_ex_id": pres_ex_id, "created_at": ts(**age), "state": state}


def oob(invi_msg_id, age, state="await-response", multi_use=False, connection_id=None):
    record = {
        "invi_msg_id": invi_msg_id,
        "created_at": ts(**age),
        "state": state,
        "multi_use": multi_use,
    }
    if connection_id:
        record["connection_id"] = connection_id
    return record


def conn(
    connection_id,
    age,
    state="invitation",
    invitation_mode="once",
    their_role="invitee",
):
    return {
        "connection_id": connection_id,
        "created_at": ts(**age),
        "state": state,
        "invitation_mode": invitation_mode,
        "their_role": their_role,
    }


class FakeAcapy:
    """In-memory ACA-Py admin API that pages and deletes like the real one."""

    def __init__(
        self,
        presentations=(),
        oob_records=(),
        connections=(),
        fail_ids=(),
        failing_phases=(),
        delete_delay=0.0,
    ):
        self.store = {
            "pres": list(presentations),
            "oob": list(oob_records),
            "conn": list(connections),
        }
        self.fail_ids = set(fail_ids)
        self.failing_phases = set(failing_phases)
        self.delete_delay = delete_delay
        self.deleted = {"pres": [], "oob": [], "conn": []}
        self.in_flight = 0
        self.max_in_flight = 0
        self.page_calls = 0

    async def _page(self, kind, limit, offset):
        self.page_calls += 1
        if kind in self.failing_phases:
            raise RuntimeError(f"{kind} listing unavailable")
        await asyncio.sleep(0)
        return list(self.store[kind][offset : offset + limit])

    async def _delete(self, kind, key, record_id):
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(self.delete_delay)
            if record_id in self.fail_ids:
                return False
            self.store[kind] = [r for r in self.store[kind] if r[key] != record_id]
            self.deleted[kind].append(record_id)
            return True
        finally:
            self.in_flight -= 1

    async def get_presentation_records_page(self, limit, offset=0):
        return await self._page("pres", limit, offset)

    async def get_oob_records_page(self, limit, offset=0):
        return await self._page("oob", limit, offset)

    async def get_connections_page(self, limit, offset=0):
        return await self._page("conn", limit, offset)

    async def delete_presentation_record(self, record_id):
        return await self._delete("pres", "pres_ex_id", record_id)

    async def delete_oob_invitation(self, record_id):
        return await self._delete("oob", "invi_msg_id", record_id)

    async def delete_connection(self, record_id):
        return await self._delete("conn", "connection_id", record_id)


async def run_cleanup(fake, settings=None, **kwargs):
    with (
        patch.object(cleanup_module, "AcapyClient", return_value=fake),
        patch.object(cleanup_module, "settings", settings or make_settings()),
    ):
        return await perform_cleanup(MagicMock(), **kwargs)


class TestConfigurationValidation:
    def test_valid_configuration(self):
        with patch.object(cleanup_module, "settings", make_settings()):
            validate_cleanup_configuration()

    @pytest.mark.parametrize(
        "override, message",
        [
            (
                {"CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS": 0},
                "CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS must be positive",
            ),
            (
                {"CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS": 0},
                "CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS must be between 1 and 10000",
            ),
            (
                {"CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS": 10001},
                "CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS must be between 1 and 10000",
            ),
            (
                {"CONTROLLER_CLEANUP_MAX_CONNECTIONS": 20001},
                "CONTROLLER_CLEANUP_MAX_CONNECTIONS must be between 1 and 20000",
            ),
            (
                {"CONTROLLER_CLEANUP_CONCURRENCY": 0},
                "CONTROLLER_CLEANUP_CONCURRENCY must be between 1 and 50",
            ),
            (
                {"CONTROLLER_CLEANUP_CONCURRENCY": 51},
                "CONTROLLER_CLEANUP_CONCURRENCY must be between 1 and 50",
            ),
            (
                {"CONTROLLER_CLEANUP_MAX_DURATION_SECONDS": 0},
                "CONTROLLER_CLEANUP_MAX_DURATION_SECONDS must be positive",
            ),
            (
                {"CONTROLLER_PRESENTATION_EXPIRE_TIME": -1},
                "CONTROLLER_PRESENTATION_EXPIRE_TIME must be positive",
            ),
        ],
    )
    def test_invalid_values_are_rejected(self, override, message):
        with patch.object(cleanup_module, "settings", make_settings(**override)):
            with pytest.raises(ValueError, match=message):
                validate_cleanup_configuration()

    def test_multiple_errors_reported_together(self):
        settings = make_settings(
            CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS=0,
            CONTROLLER_CLEANUP_CONCURRENCY=0,
        )
        with patch.object(cleanup_module, "settings", settings):
            with pytest.raises(ValueError) as exc_info:
                validate_cleanup_configuration()
        assert "RETENTION_HOURS" in str(exc_info.value)
        assert "CONCURRENCY" in str(exc_info.value)


class TestTimestampParsing:
    @pytest.mark.parametrize(
        "value",
        [
            "2024-01-01T12:00:00Z",
            "2024-01-01T12:00:00+00:00",
            "2024-01-01T12:00:00.123456Z",
            "2024-01-01T12:00:00",
        ],
    )
    def test_supported_formats_are_timezone_aware(self, value):
        parsed = _parse_record_timestamp(value, "rec")
        assert parsed is not None
        assert parsed.tzinfo is not None

    def test_invalid_timestamp_returns_none(self):
        assert _parse_record_timestamp("not-a-date", "rec") is None


class TestPresentationRecords:
    @pytest.mark.asyncio
    async def test_deletes_only_records_older_than_retention(self):
        fake = FakeAcapy(presentations=[pres("old", OLD), pres("recent", RECENT)])

        stats = await run_cleanup(fake)

        assert fake.deleted["pres"] == ["old"]
        assert stats["total_presentation_records"] == 2
        assert stats["cleaned_presentation_records"] == 1
        assert stats["has_more"] is False

    @pytest.mark.asyncio
    async def test_records_without_or_with_bad_timestamp_are_skipped(self):
        broken = {"pres_ex_id": "bad", "created_at": "garbage"}
        missing = {"pres_ex_id": "missing"}
        fake = FakeAcapy(presentations=[broken, missing, pres("old", OLD)])

        stats = await run_cleanup(fake)

        assert fake.deleted["pres"] == ["old"]
        assert stats["failed_cleanups"] == 0


class TestPaginationWhileDeleting:
    @pytest.mark.asyncio
    async def test_all_stale_records_across_pages_are_deleted(self):
        records = [pres(f"old-{i}", OLD) for i in range(PAGE_SIZE * 2 + 50)]
        fake = FakeAcapy(presentations=records)

        stats = await run_cleanup(fake)

        assert len(fake.deleted["pres"]) == len(records)
        assert fake.store["pres"] == []
        assert stats["cleaned_presentation_records"] == len(records)

    @pytest.mark.asyncio
    async def test_interleaved_recent_records_do_not_hide_stale_ones(self):
        records = [
            pres(f"rec-{i}", OLD if i % 3 else RECENT) for i in range(PAGE_SIZE * 3)
        ]
        fake = FakeAcapy(presentations=records)

        await run_cleanup(fake)

        remaining = {r["pres_ex_id"] for r in fake.store["pres"]}
        assert remaining == {f"rec-{i}" for i in range(PAGE_SIZE * 3) if i % 3 == 0}

    @pytest.mark.asyncio
    async def test_failed_deletions_do_not_cause_infinite_loop(self):
        records = [pres(f"old-{i}", OLD) for i in range(PAGE_SIZE + 10)]
        fake = FakeAcapy(presentations=records, fail_ids={"old-0", "old-1"})

        stats = await run_cleanup(fake)

        assert stats["failed_cleanups"] == 2
        assert stats["cleaned_presentation_records"] == len(records) - 2
        assert {r["pres_ex_id"] for r in fake.store["pres"]} == {"old-0", "old-1"}


class TestOobRecords:
    @pytest.mark.asyncio
    async def test_unused_invitations_deleted_after_expiry(self):
        fake = FakeAcapy(
            oob_records=[oob("expired", EXPIRED), oob("fresh", FRESH)],
        )

        stats = await run_cleanup(fake)

        assert fake.deleted["oob"] == ["expired"]
        assert stats["cleaned_oob_records"] == 1

    @pytest.mark.asyncio
    async def test_used_invitations_deleted_only_after_retention(self):
        fake = FakeAcapy(
            oob_records=[
                oob("done-recent", EXPIRED, state="done"),
                oob("done-old", OLD, state="done"),
            ],
        )

        await run_cleanup(fake)

        assert fake.deleted["oob"] == ["done-old"]

    @pytest.mark.asyncio
    async def test_multi_use_invitations_are_never_deleted(self):
        fake = FakeAcapy(oob_records=[oob("multi", OLD, multi_use=True)])

        await run_cleanup(fake)

        assert fake.deleted["oob"] == []

    @pytest.mark.asyncio
    async def test_invitations_linked_to_a_connection_wait_for_retention(self):
        fake = FakeAcapy(
            oob_records=[
                oob("linked-expired", EXPIRED, connection_id="conn-1"),
                oob("linked-old", OLD, connection_id="conn-2"),
            ],
        )

        await run_cleanup(fake)

        assert fake.deleted["oob"] == ["linked-old"]


class TestConnections:
    @pytest.mark.asyncio
    async def test_unused_invitations_deleted_after_expiry(self):
        fake = FakeAcapy(
            connections=[conn("expired", EXPIRED), conn("fresh", FRESH)],
        )

        await run_cleanup(fake)

        assert fake.deleted["conn"] == ["expired"]

    @pytest.mark.asyncio
    async def test_stuck_connections_in_any_state_deleted_after_retention(self):
        fake = FakeAcapy(
            connections=[
                conn("request-old", OLD, state="request"),
                conn("active-old", OLD, state="active"),
                conn("active-recent", EXPIRED, state="active"),
                conn("response-recent", RECENT, state="response"),
            ],
        )

        await run_cleanup(fake)

        assert sorted(fake.deleted["conn"]) == ["active-old", "request-old"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", ["multi", "static"])
    async def test_reusable_invitation_connections_are_never_deleted(self, mode):
        fake = FakeAcapy(
            connections=[conn("reusable", OLD, state="active", invitation_mode=mode)]
        )

        await run_cleanup(fake)

        assert fake.deleted["conn"] == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("their_role", ["inviter", None])
    async def test_connections_not_initiated_by_vc_authn_are_never_deleted(
        self, their_role
    ):
        fake = FakeAcapy(
            connections=[
                conn("received", OLD, state="active", their_role=their_role),
                conn("received-invite", OLD, their_role=their_role),
            ]
        )

        await run_cleanup(fake)

        assert fake.deleted["conn"] == []


class TestLimitsAndBudget:
    @pytest.mark.asyncio
    async def test_presentation_limit_sets_has_more(self):
        fake = FakeAcapy(presentations=[pres(f"old-{i}", OLD) for i in range(10)])

        stats = await run_cleanup(fake, max_presentation_records=3)

        assert len(fake.deleted["pres"]) == 3
        assert stats["hit_presentation_limit"] is True
        assert stats["has_more"] is True

    @pytest.mark.asyncio
    async def test_connection_limit_applies_to_oob_and_connection_phases(self):
        fake = FakeAcapy(
            oob_records=[oob(f"oob-{i}", EXPIRED) for i in range(5)],
            connections=[conn(f"conn-{i}", EXPIRED) for i in range(5)],
        )

        stats = await run_cleanup(fake, max_connections=2)

        assert len(fake.deleted["oob"]) == 2
        assert len(fake.deleted["conn"]) == 2
        assert stats["hit_connection_limit"] is True
        assert stats["has_more"] is True

    @pytest.mark.asyncio
    async def test_time_budget_stops_cleanup(self):
        fake = FakeAcapy(
            presentations=[pres(f"old-{i}", OLD) for i in range(PAGE_SIZE * 3)],
            connections=[conn("expired", EXPIRED)],
        )
        clock = iter([0, 0, 0, 1000, 1000, 1000, 1000])
        settings = make_settings(CONTROLLER_CLEANUP_MAX_DURATION_SECONDS=10)
        fake_time = SimpleNamespace(monotonic=lambda: next(clock))

        with patch.object(cleanup_module, "time", fake_time):
            stats = await run_cleanup(fake, settings=settings)

        assert stats["hit_time_budget"] is True
        assert stats["has_more"] is True
        assert len(fake.deleted["pres"]) == PAGE_SIZE
        assert fake.deleted["conn"] == []

    @pytest.mark.asyncio
    async def test_deletes_run_with_bounded_concurrency(self):
        fake = FakeAcapy(
            presentations=[pres(f"old-{i}", OLD) for i in range(40)],
            delete_delay=0.005,
        )
        settings = make_settings(CONTROLLER_CLEANUP_CONCURRENCY=3)

        await run_cleanup(fake, settings=settings)

        assert fake.max_in_flight == 3
        assert fake.store["pres"] == []


class TestDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_reports_without_deleting(self):
        fake = FakeAcapy(
            presentations=[pres("old", OLD), pres("recent", RECENT)],
            oob_records=[oob("expired", EXPIRED)],
            connections=[conn("expired", EXPIRED)],
        )

        stats = await run_cleanup(fake, dry_run=True)

        assert fake.deleted == {"pres": [], "oob": [], "conn": []}
        assert stats["cleaned_presentation_records"] == 1
        assert stats["cleaned_oob_records"] == 1
        assert stats["cleaned_connections"] == 1

    @pytest.mark.asyncio
    async def test_dry_run_paginates_through_all_records(self):
        fake = FakeAcapy(presentations=[pres(f"old-{i}", OLD) for i in range(250)])

        stats = await run_cleanup(fake, dry_run=True)

        assert stats["total_presentation_records"] == 250
        assert stats["cleaned_presentation_records"] == 250


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_listing_failure_does_not_stop_other_phases(self):
        fake = FakeAcapy(
            presentations=[pres("old", OLD)],
            connections=[conn("expired", EXPIRED)],
            failing_phases={"pres"},
        )

        stats = await run_cleanup(fake)

        assert fake.deleted["conn"] == ["expired"]
        assert stats["has_more"] is True
        assert any("presentation_records" in e for e in stats["errors"])

    @pytest.mark.asyncio
    async def test_reported_errors_are_capped(self):
        records = [pres(f"old-{i}", OLD) for i in range(MAX_REPORTED_ERRORS + 20)]
        fake = FakeAcapy(
            presentations=records, fail_ids={r["pres_ex_id"] for r in records}
        )

        stats = await run_cleanup(fake)

        assert stats["failed_cleanups"] == len(records)
        assert len(stats["errors"]) == MAX_REPORTED_ERRORS


class TestNonBlocking:
    @pytest.mark.asyncio
    async def test_event_loop_stays_responsive_during_cleanup(self):
        fake = FakeAcapy(
            presentations=[pres(f"old-{i}", OLD) for i in range(50)],
            delete_delay=0.002,
        )
        ticks = []
        done = asyncio.Event()

        async def ticker():
            while not done.is_set():
                start = asyncio.get_running_loop().time()
                await asyncio.sleep(0.005)
                ticks.append(asyncio.get_running_loop().time() - start)

        async def cleanup():
            try:
                await run_cleanup(fake)
            finally:
                done.set()

        await asyncio.gather(cleanup(), ticker())

        assert ticks
        assert max(ticks) < 0.1
