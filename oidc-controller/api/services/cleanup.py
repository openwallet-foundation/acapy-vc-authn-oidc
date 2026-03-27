"""Cleanup functions for presentation records and connections."""

from datetime import UTC, datetime, timedelta
from typing import TypedDict

import httpx
import structlog

from ..core.acapy.client import AcapyClient
from ..core.config import settings

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


class CleanupStats(TypedDict):
    """Statistics for cleanup operations."""

    total_presentation_records: int
    cleaned_presentation_records: int
    total_connections: int
    cleaned_connections: int
    failed_cleanups: int
    errors: list[str]
    hit_presentation_limit: bool
    hit_connection_limit: bool


def validate_cleanup_configuration():
    """Validate cleanup configuration settings at startup."""
    errors = []

    # Validate retention hours (should be positive)
    retention_hours = settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS
    if retention_hours <= 0:
        errors.append(
            f"CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS must be positive, got {retention_hours}"
        )

    # Validate resource limits (should be positive and reasonable)
    max_records = settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS
    if not (1 <= max_records <= 10000):  # Reasonable upper bound
        errors.append(
            f"CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS must be between 1 and 10000, got {max_records}"
        )

    max_connections = settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS
    if not (1 <= max_connections <= 20000):  # Reasonable upper bound
        errors.append(
            f"CONTROLLER_CLEANUP_MAX_CONNECTIONS must be between 1 and 20000, got {max_connections}"
        )

    # Validate expiration time (should be positive)
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


def _should_clean_record(record: dict, cutoff_time: datetime) -> bool:
    """Check if a record should be cleaned up based on age."""
    created_at_str = record.get("created_at")
    if not created_at_str:
        raise ValueError(
            f"Record {record.get('pres_ex_id', 'unknown')} missing created_at timestamp"
        )

    record_time = _parse_record_timestamp(
        created_at_str, record.get("pres_ex_id", "unknown")
    )
    # Invalid timestamp format - just skip this record (don't treat as failure)
    return record_time < cutoff_time if record_time else False


async def _cleanup_single_presentation_record(
    client: "AcapyClient", record: dict, stats: CleanupStats, dry_run: bool
) -> None:
    """Clean up a single presentation record and update stats."""
    pres_ex_id = record.get("pres_ex_id")

    if dry_run:
        stats["cleaned_presentation_records"] += 1
        logger.info(
            "dry_run: would delete presentation record",
            pres_ex_id=pres_ex_id,
            phase="presentation_records",
        )
        return

    try:
        (
            presentation_deleted,
            _,
            errors,
        ) = await client.delete_presentation_record_and_connection(pres_ex_id, None)

        if presentation_deleted:
            stats["cleaned_presentation_records"] += 1
            logger.debug(
                "Cleaned up old presentation record",
                pres_ex_id=pres_ex_id,
                phase="presentation_records",
            )
        else:
            stats["failed_cleanups"] += 1

        # Log any errors from the cleanup operation
        for error in errors:
            stats["errors"].append(error)
            logger.warning(
                "Cleanup operation error", error=error, phase="presentation_records"
            )

    except Exception as record_error:
        stats["failed_cleanups"] += 1
        error_msg = f"Error processing record {pres_ex_id}: {record_error}"
        stats["errors"].append(error_msg)
        logger.error(
            "Error processing presentation record",
            pres_ex_id=pres_ex_id,
            error=str(record_error),
            phase="presentation_records",
        )


async def _cleanup_presentation_records(
    client: "AcapyClient", stats: CleanupStats, max_records: int, dry_run: bool
) -> datetime:
    """Clean up old presentation records phase."""
    phase_start = datetime.now(UTC)

    # Get configuration
    retention_hours = settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS
    cutoff_time = datetime.now(UTC) - timedelta(hours=retention_hours)

    # Fetch records
    records = await client.get_all_presentation_records()
    stats["total_presentation_records"] = len(records)

    logger.info(
        "Found presentation records for cleanup evaluation",
        phase="presentation_records",
        total_records=len(records),
        fetch_duration_ms=int((datetime.now(UTC) - phase_start).total_seconds() * 1000),
    )

    # Apply resource limits
    if len(records) > max_records:
        stats["hit_presentation_limit"] = True
        records = records[:max_records]
        logger.warning(
            "Limited presentation record processing due to resource limits",
            max_allowed=max_records,
            total_found=stats["total_presentation_records"],
            phase="presentation_records",
        )

    # Process each record
    for record in records:
        try:
            if _should_clean_record(record, cutoff_time):
                await _cleanup_single_presentation_record(
                    client, record, stats, dry_run
                )
            else:
                logger.debug(
                    "Record too recent to clean up",
                    pres_ex_id=record.get("pres_ex_id"),
                    phase="presentation_records",
                )
        except Exception as record_error:
            # Handle cases where record processing fails (e.g., missing timestamp)
            stats["failed_cleanups"] += 1
            error_msg = f"Error processing record {record.get('pres_ex_id', 'unknown')}: {record_error}"
            stats["errors"].append(error_msg)
            logger.error(
                "Error processing presentation record",
                pres_ex_id=record.get("pres_ex_id", "unknown"),
                error=str(record_error),
                phase="presentation_records",
            )

    return phase_start


async def _cleanup_single_connection(
    client: "AcapyClient",
    connection: dict,
    cutoff_time: datetime,
    stats: CleanupStats,
    dry_run: bool,
) -> None:
    """Clean up a single connection and update stats."""
    connection_id = connection.get("connection_id")
    created_at_str = connection.get("created_at")

    if not created_at_str:
        logger.warning(
            "Connection missing created_at timestamp", connection_id=connection_id
        )
        return

    connection_time = _parse_record_timestamp(created_at_str, connection_id)
    if connection_time is None:
        return

    if connection_time < cutoff_time:
        if dry_run:
            stats["cleaned_connections"] += 1
            logger.info(
                "dry_run: would delete connection invitation",
                connection_id=connection_id,
                phase="connections",
            )
            return

        logger.debug(
            "Cleaning up expired connection invitation",
            connection_id=connection_id,
            phase="connections",
        )

        try:
            connection_deleted = await client.delete_connection(connection_id)

            if connection_deleted:
                stats["cleaned_connections"] += 1
                logger.debug(
                    "Cleaned up expired connection invitation",
                    connection_id=connection_id,
                    phase="connections",
                )
            else:
                stats["failed_cleanups"] += 1
                error_msg = (
                    f"Failed to delete expired connection invitation {connection_id}"
                )
                stats["errors"].append(error_msg)
                logger.warning(
                    "Failed to delete expired connection invitation",
                    connection_id=connection_id,
                    phase="connections",
                )
        except Exception as connection_error:
            stats["failed_cleanups"] += 1
            error_msg = (
                f"Error processing connection {connection_id}: {connection_error}"
            )
            stats["errors"].append(error_msg)
            logger.error(
                "Error processing connection",
                connection_id=connection_id,
                error=str(connection_error),
                phase="connections",
            )
    else:
        logger.debug(
            "Connection invitation too recent to clean up",
            connection_id=connection_id,
            phase="connections",
        )


async def _cleanup_connections(
    client: "AcapyClient",
    stats: CleanupStats,
    presentation_phase_start: datetime,
    max_connections: int,
    dry_run: bool,
) -> None:
    """Clean up expired connections phase."""
    phase_start = datetime.now(UTC)

    # Get configuration
    expire_seconds = settings.CONTROLLER_PRESENTATION_EXPIRE_TIME
    cutoff_time = datetime.now(UTC) - timedelta(seconds=expire_seconds)

    logger.info(
        "Starting connection cleanup with API-level filtering",
        phase="connections",
        presentation_cleanup_duration_ms=int(
            (phase_start - presentation_phase_start).total_seconds() * 1000
        ),
    )

    total_connections = 0
    processed_connections = 0

    async for connection_batch in client.get_connections_batched(state="invitation"):
        total_connections += len(connection_batch)
        logger.debug(
            f"Processing batch of {len(connection_batch)} invitation connections"
        )

        for connection in connection_batch:
            # Apply resource limit check
            if processed_connections >= max_connections:
                stats["hit_connection_limit"] = True
                logger.warning(
                    "Hit connection processing limit, stopping early",
                    max_allowed=max_connections,
                    total_found=total_connections,
                    phase="connections",
                )
                break

            processed_connections += 1
            await _cleanup_single_connection(
                client, connection, cutoff_time, stats, dry_run
            )

        # Break out of batch loop if we hit the limit
        if stats["hit_connection_limit"]:
            break

    # Set total connections count after processing all batches
    stats["total_connections"] = total_connections
    phase_duration = datetime.now(UTC) - phase_start
    logger.info(
        "Processed invitation connections",
        phase="connections",
        processed_connections=processed_connections,
        total_connections=total_connections,
        connection_cleanup_duration_ms=int(phase_duration.total_seconds() * 1000),
    )


async def perform_cleanup(
    http_client: httpx.AsyncClient,
    dry_run: bool = False,
    max_presentation_records: int | None = None,
    max_connections: int | None = None,
) -> CleanupStats:
    """
    Perform comprehensive cleanup of expired presentation data and connections.

    Args:
        http_client: The shared httpx AsyncClient
        dry_run: If True, only report what would be deleted without actual deletion
        max_presentation_records: Override default max presentation records limit
        max_connections: Override default max connections limit

    Returns:
        CleanupStats with detailed information about cleanup operations
    """
    start_time = datetime.now(UTC)

    # Resolve effective limits: use caller override if provided, otherwise fall back to settings
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

    logger.info(
        "Starting cleanup of old presentation records and expired connections",
        dry_run=dry_run,
        max_presentation_records=effective_max_records,
        max_connections=effective_max_connections,
    )

    # Initialize stats tracking
    cleanup_stats: CleanupStats = {
        "total_presentation_records": 0,
        "cleaned_presentation_records": 0,
        "total_connections": 0,
        "cleaned_connections": 0,
        "failed_cleanups": 0,
        "errors": [],
        "hit_presentation_limit": False,
        "hit_connection_limit": False,
    }

    client = AcapyClient(http_client)

    try:
        presentation_phase_start = await _cleanup_presentation_records(
            client, cleanup_stats, effective_max_records, dry_run
        )
        await _cleanup_connections(
            client,
            cleanup_stats,
            presentation_phase_start,
            effective_max_connections,
            dry_run,
        )

    except Exception as e:
        error_msg = f"Cleanup operation failed: {e}"
        cleanup_stats["errors"].append(error_msg)
        logger.error("Cleanup operation failed", error=str(e))

    limit_info = ""
    if cleanup_stats["hit_presentation_limit"] or cleanup_stats["hit_connection_limit"]:
        limits_hit = []
        if cleanup_stats["hit_presentation_limit"]:
            limits_hit.append("presentation record limit")
        if cleanup_stats["hit_connection_limit"]:
            limits_hit.append("connection limit")
        limit_info = f" (hit {' and '.join(limits_hit)})"

    total_duration = datetime.now(UTC) - start_time
    logger.info(
        f"Cleanup completed{limit_info}",
        operation="cleanup_completed",
        total_duration_ms=int(total_duration.total_seconds() * 1000),
        cleaned_presentation_records=cleanup_stats["cleaned_presentation_records"],
        cleaned_connections=cleanup_stats["cleaned_connections"],
        failed_cleanups=cleanup_stats["failed_cleanups"],
        total_presentation_records=cleanup_stats["total_presentation_records"],
        total_connections=cleanup_stats["total_connections"],
        hit_presentation_limit=cleanup_stats["hit_presentation_limit"],
        hit_connection_limit=cleanup_stats["hit_connection_limit"],
        error_count=len(cleanup_stats["errors"]),
    )
    return cleanup_stats
