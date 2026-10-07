"""Cleanup of stale ACA-Py presentation exchanges, OOB invitations and connections."""

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import TypedDict

import httpx
import structlog

from ..core.acapy.client import AcapyClient
from ..core.config import settings

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

PAGE_SIZE = 100
MAX_REPORTED_ERRORS = 50
UNUSED_OOB_STATES = {"initial", "await-response"}
UNUSED_CONNECTION_STATES = {"invitation"}
REUSABLE_INVITATION_MODES = {"multi", "static"}
# Stored their_role (RFC 160) when VC-AuthN issued the invitation
INVITEE_ROLE = "invitee"


class CleanupStats(TypedDict):
    """Statistics for cleanup operations."""

    total_presentation_records: int
    cleaned_presentation_records: int
    total_oob_records: int
    cleaned_oob_records: int
    total_connections: int
    cleaned_connections: int
    failed_cleanups: int
    errors: list[str]
    hit_presentation_limit: bool
    hit_connection_limit: bool
    hit_time_budget: bool
    has_more: bool


def validate_cleanup_configuration():
    """Validate cleanup configuration settings at startup."""
    errors = []

    retention_hours = settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS
    if retention_hours <= 0:
        errors.append(
            f"CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS must be positive, got {retention_hours}"
        )

    max_records = settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS
    if not (1 <= max_records <= 10000):
        errors.append(
            f"CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS must be between 1 and 10000, got {max_records}"
        )

    max_connections = settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS
    if not (1 <= max_connections <= 20000):
        errors.append(
            f"CONTROLLER_CLEANUP_MAX_CONNECTIONS must be between 1 and 20000, got {max_connections}"
        )

    concurrency = settings.CONTROLLER_CLEANUP_CONCURRENCY
    if not (1 <= concurrency <= 50):
        errors.append(
            f"CONTROLLER_CLEANUP_CONCURRENCY must be between 1 and 50, got {concurrency}"
        )

    max_duration = settings.CONTROLLER_CLEANUP_MAX_DURATION_SECONDS
    if max_duration <= 0:
        errors.append(
            f"CONTROLLER_CLEANUP_MAX_DURATION_SECONDS must be positive, got {max_duration}"
        )

    expire_time = settings.CONTROLLER_PRESENTATION_EXPIRE_TIME
    if expire_time <= 0:
        errors.append(
            f"CONTROLLER_PRESENTATION_EXPIRE_TIME must be positive, got {expire_time}"
        )

    if errors:
        error_msg = "Invalid cleanup configuration: " + "; ".join(errors)
        logger.error(error_msg)
        raise ValueError(error_msg)

    logger.info(
        "Cleanup configuration validated successfully",
        retention_hours=retention_hours,
        max_presentation_records=max_records,
        max_connections=max_connections,
        concurrency=concurrency,
        max_duration_seconds=max_duration,
        expire_time_seconds=expire_time,
        operation="config_validation",
    )


def _parse_record_timestamp(created_at_str: str, record_id: str) -> datetime | None:
    """Parse ISO timestamp from ACA-Py record, handling various formats."""
    try:
        if created_at_str.endswith("Z"):
            created_at_str = created_at_str[:-1] + "+00:00"
        record_time = datetime.fromisoformat(created_at_str)
        if record_time.tzinfo is None:
            record_time = record_time.replace(tzinfo=UTC)
        return record_time
    except ValueError as parse_error:
        logger.warning(
            "Failed to parse timestamp for record",
            timestamp=created_at_str,
            record_id=record_id,
            error=str(parse_error),
        )
        return None


def _created_before(record: dict, cutoff: datetime, id_key: str) -> bool:
    """Return True if the record was created before the cutoff (unparseable -> False)."""
    created_at_str = record.get("created_at")
    if not created_at_str:
        return False
    record_time = _parse_record_timestamp(created_at_str, record.get(id_key, "unknown"))
    return record_time is not None and record_time < cutoff


def _record_error(stats: CleanupStats, message: str) -> None:
    if len(stats["errors"]) < MAX_REPORTED_ERRORS:
        stats["errors"].append(message)


async def _delete_one(
    delete: Callable[[str], Awaitable[bool]],
    record_id: str,
    semaphore: asyncio.Semaphore,
    phase: str,
    stats: CleanupStats,
) -> bool:
    async with semaphore:
        try:
            deleted = await delete(record_id)
        except Exception as e:
            logger.error(
                "Error deleting record", phase=phase, record_id=record_id, error=str(e)
            )
            deleted = False

    if not deleted:
        stats["failed_cleanups"] += 1
        stats["has_more"] = True
        _record_error(stats, f"Failed to delete {phase} record {record_id}")
    return deleted


async def _sweep(
    *,
    phase: str,
    fetch_page: Callable[[int, int], Awaitable[list[dict]]],
    id_key: str,
    is_stale: Callable[[dict], bool],
    delete: Callable[[str], Awaitable[bool]],
    max_deletes: int,
    deadline: float,
    semaphore: asyncio.Semaphore,
    dry_run: bool,
    stats: CleanupStats,
    total_key: str,
    cleaned_key: str,
) -> bool:
    """Page through records deleting stale ones.

    Returns True if the sweep stopped early (limit or time budget) and more
    stale records may remain.
    """
    phase_start = time.monotonic()
    offset = 0
    selected = 0

    def budget_exhausted() -> bool:
        stats["hit_time_budget"] = True
        logger.warning("Cleanup time budget exhausted", phase=phase)
        return True

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return budget_exhausted()

        try:
            page = await asyncio.wait_for(fetch_page(PAGE_SIZE, offset), remaining)
        except TimeoutError:
            return budget_exhausted()
        stats[total_key] += len(page)

        stale_ids = [r[id_key] for r in page if r.get(id_key) and is_stale(r)]
        stale_ids = stale_ids[: max_deletes - selected]
        selected += len(stale_ids)

        if dry_run:
            for record_id in stale_ids:
                logger.info(
                    "dry_run: would delete record", phase=phase, record_id=record_id
                )
            stats[cleaned_key] += len(stale_ids)
            deleted = 0
        elif stale_ids:
            tasks = [
                asyncio.create_task(
                    _delete_one(delete, record_id, semaphore, phase, stats)
                )
                for record_id in stale_ids
            ]
            done, pending = await asyncio.wait(
                tasks, timeout=max(deadline - time.monotonic(), 0)
            )
            for task in pending:
                task.cancel()
            # Let cancelled requests unwind before the lock is released
            await asyncio.gather(*pending, return_exceptions=True)
            deleted = sum(task.result() for task in done)
            stats[cleaned_key] += deleted
            if pending:
                logger.warning(
                    "Cancelled outstanding deletions",
                    phase=phase,
                    cancelled=len(pending),
                )
                return budget_exhausted()
        else:
            deleted = 0

        if selected >= max_deletes:
            logger.warning(
                "Cleanup limit reached", phase=phase, max_deletes=max_deletes
            )
            return True

        if len(page) < PAGE_SIZE:
            break

        # Deleted records no longer occupy positions in the listing
        offset += len(page) - deleted

    logger.info(
        "Cleanup phase completed",
        phase=phase,
        examined=stats[total_key],
        cleaned=stats[cleaned_key],
        duration_ms=int((time.monotonic() - phase_start) * 1000),
    )
    return False


async def perform_cleanup(
    http_client: httpx.AsyncClient,
    dry_run: bool = False,
    max_presentation_records: int | None = None,
    max_connections: int | None = None,
) -> CleanupStats:
    """
    Delete stale ACA-Py records created by VC-AuthN.

    Phases, in order:
    - verifier presentation exchanges older than the retention period
    - sender OOB invitations: connectionless unused ones after the presentation
      expiry time, any other after the retention period (deleting an OOB
      invitation also deletes connections created from it)
    - connections where VC-AuthN was the inviter: unused invitations after the
      presentation expiry time, any other state after the retention period

    Multi-use/static invitations and their connections are never deleted.

    Args:
        http_client: The shared httpx AsyncClient
        dry_run: If True, only report what would be deleted without actual deletion
        max_presentation_records: Override max presentation records deleted per run
        max_connections: Override max OOB records and connections deleted per run

    Returns:
        CleanupStats with detailed information about cleanup operations
    """
    start = time.monotonic()
    deadline = start + settings.CONTROLLER_CLEANUP_MAX_DURATION_SECONDS

    effective_max_records = (
        max_presentation_records
        if max_presentation_records is not None
        else settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS
    )
    effective_max_connections = (
        max_connections
        if max_connections is not None
        else settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS
    )

    now = datetime.now(UTC)
    retention_cutoff = now - timedelta(
        hours=settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS
    )
    expiry_cutoff = now - timedelta(
        seconds=settings.CONTROLLER_PRESENTATION_EXPIRE_TIME
    )

    logger.info(
        "Starting cleanup of stale ACA-Py records",
        dry_run=dry_run,
        max_presentation_records=effective_max_records,
        max_connections=effective_max_connections,
    )

    stats: CleanupStats = {
        "total_presentation_records": 0,
        "cleaned_presentation_records": 0,
        "total_oob_records": 0,
        "cleaned_oob_records": 0,
        "total_connections": 0,
        "cleaned_connections": 0,
        "failed_cleanups": 0,
        "errors": [],
        "hit_presentation_limit": False,
        "hit_connection_limit": False,
        "hit_time_budget": False,
        "has_more": False,
    }

    client = AcapyClient(http_client)
    semaphore = asyncio.Semaphore(settings.CONTROLLER_CLEANUP_CONCURRENCY)

    def oob_is_stale(record: dict) -> bool:
        if record.get("multi_use"):
            return False
        # Linked connections may still be mid-flow; only the retention period is safe
        unused = record.get("state") in UNUSED_OOB_STATES
        if unused and not record.get("connection_id"):
            return _created_before(record, expiry_cutoff, "invi_msg_id")
        return _created_before(record, retention_cutoff, "invi_msg_id")

    def connection_is_stale(record: dict) -> bool:
        if record.get("their_role") != INVITEE_ROLE:
            return False
        if record.get("invitation_mode") in REUSABLE_INVITATION_MODES:
            return False
        if record.get("state") in UNUSED_CONNECTION_STATES:
            return _created_before(record, expiry_cutoff, "connection_id")
        return _created_before(record, retention_cutoff, "connection_id")

    phases = [
        dict(
            phase="presentation_records",
            fetch_page=client.get_presentation_records_page,
            id_key="pres_ex_id",
            is_stale=lambda r: _created_before(r, retention_cutoff, "pres_ex_id"),
            delete=client.delete_presentation_record,
            max_deletes=effective_max_records,
            total_key="total_presentation_records",
            cleaned_key="cleaned_presentation_records",
            limit_flag="hit_presentation_limit",
        ),
        dict(
            phase="oob_records",
            fetch_page=client.get_oob_records_page,
            id_key="invi_msg_id",
            is_stale=oob_is_stale,
            delete=client.delete_oob_invitation,
            max_deletes=effective_max_connections,
            total_key="total_oob_records",
            cleaned_key="cleaned_oob_records",
            limit_flag="hit_connection_limit",
        ),
        dict(
            phase="connections",
            fetch_page=client.get_connections_page,
            id_key="connection_id",
            is_stale=connection_is_stale,
            delete=client.delete_connection,
            max_deletes=effective_max_connections,
            total_key="total_connections",
            cleaned_key="cleaned_connections",
            limit_flag="hit_connection_limit",
        ),
    ]

    for phase_config in phases:
        limit_flag = phase_config.pop("limit_flag")
        try:
            stopped_early = await _sweep(
                **phase_config,
                deadline=deadline,
                semaphore=semaphore,
                dry_run=dry_run,
                stats=stats,
            )
        except Exception as e:
            logger.error(
                "Cleanup phase failed", phase=phase_config["phase"], error=str(e)
            )
            _record_error(stats, f"Cleanup phase {phase_config['phase']} failed: {e}")
            stats["has_more"] = True
            continue

        if stopped_early:
            stats["has_more"] = True
            if stats["hit_time_budget"]:
                break
            stats[limit_flag] = True

    logger.info(
        "Cleanup completed",
        operation="cleanup_completed",
        dry_run=dry_run,
        total_duration_ms=int((time.monotonic() - start) * 1000),
        cleaned_presentation_records=stats["cleaned_presentation_records"],
        cleaned_oob_records=stats["cleaned_oob_records"],
        cleaned_connections=stats["cleaned_connections"],
        failed_cleanups=stats["failed_cleanups"],
        total_presentation_records=stats["total_presentation_records"],
        total_oob_records=stats["total_oob_records"],
        total_connections=stats["total_connections"],
        hit_presentation_limit=stats["hit_presentation_limit"],
        hit_connection_limit=stats["hit_connection_limit"],
        hit_time_budget=stats["hit_time_budget"],
        has_more=stats["has_more"],
        error_count=len(stats["errors"]),
    )
    return stats
