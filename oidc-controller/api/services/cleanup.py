"""Background cleanup service for presentation records."""

from datetime import datetime, timedelta, UTC

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.redis import RedisJobStore
from apscheduler.triggers.interval import IntervalTrigger

from ..core.config import settings
from ..core.acapy.client import AcapyClient

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


async def cleanup_old_presentation_records() -> dict:
    """Clean up presentation records and expired connection invitations."""
    logger.info(
        "Starting background cleanup of old presentation records and expired connections"
    )

    client = AcapyClient()
    presentation_retention_hours = (
        settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS
    )
    connection_expiry_seconds = settings.CONTROLLER_PRESENTATION_EXPIRE_TIME

    presentation_cutoff = datetime.now(UTC) - timedelta(
        hours=presentation_retention_hours
    )
    connection_cutoff = datetime.now(UTC) - timedelta(seconds=connection_expiry_seconds)

    # Resource limits to prevent excessive processing
    MAX_PRESENTATION_RECORDS_PER_CLEANUP = 1000
    MAX_CONNECTIONS_PER_CLEANUP = 2000

    cleanup_stats = {
        "total_presentation_records": 0,
        "cleaned_presentation_records": 0,
        "total_connections": 0,
        "cleaned_connections": 0,
        "failed_cleanups": 0,
        "errors": [],
        "hit_presentation_limit": False,
        "hit_connection_limit": False,
    }

    try:
        # Phase 1: Clean up old presentation records
        records = client.get_all_presentation_records()
        cleanup_stats["total_presentation_records"] = len(records)

        logger.info(f"Found {len(records)} presentation records for cleanup evaluation")

        # Apply resource limit to presentation records
        if len(records) > MAX_PRESENTATION_RECORDS_PER_CLEANUP:
            cleanup_stats["hit_presentation_limit"] = True
            records = records[:MAX_PRESENTATION_RECORDS_PER_CLEANUP]
            logger.warning(
                f"Limited presentation record processing to {MAX_PRESENTATION_RECORDS_PER_CLEANUP} records "
                f"out of {cleanup_stats['total_presentation_records']} total"
            )

        for record in records:
            try:
                # Parse the creation time - ACA-Py uses ISO format
                created_at_str = record.get("created_at")
                # Parse ISO timestamp (handle both with and without timezone)
                try:
                    if created_at_str.endswith("Z"):
                        created_at_str = created_at_str[:-1] + "+00:00"
                    record_time = datetime.fromisoformat(created_at_str)
                    if record_time.tzinfo is None:
                        record_time = record_time.replace(tzinfo=UTC)
                except ValueError as parse_error:
                    logger.warning(
                        f"Failed to parse timestamp {created_at_str} for record {record.get('pres_ex_id')}: {parse_error}"
                    )
                    continue

                # Check if record is old enough to clean up
                if record_time < presentation_cutoff:
                    pres_ex_id = record.get("pres_ex_id")
                    presentation_deleted, _, errors = (
                        client.delete_presentation_record_and_connection(
                            pres_ex_id, None
                        )
                    )

                    if presentation_deleted:
                        cleanup_stats["cleaned_presentation_records"] += 1
                        logger.debug(f"Cleaned up old presentation record {pres_ex_id}")
                    else:
                        cleanup_stats["failed_cleanups"] += 1
                        # Don't add our own error message if the wrapper function provides errors
                        if not errors:
                            error_msg = (
                                f"Failed to delete presentation record {pres_ex_id}"
                            )
                            cleanup_stats["errors"].append(error_msg)
                            logger.warning(error_msg)

                    # Log any additional errors from the cleanup operation
                    for error in errors:
                        cleanup_stats["errors"].append(error)
                        logger.warning(f"Cleanup error: {error}")
                else:
                    logger.debug(
                        f"Record {record.get('pres_ex_id')} is too recent to clean up"
                    )

            except Exception as record_error:
                cleanup_stats["failed_cleanups"] += 1
                error_msg = f"Error processing record {record.get('pres_ex_id', 'unknown')}: {record_error}"
                cleanup_stats["errors"].append(error_msg)
                logger.error(error_msg)

        # Phase 2: Clean up expired connection invitations
        total_connections = 0
        processed_connections = 0

        logger.info("Starting connection cleanup with API-level filtering")

        for connection_batch in client.get_connections_batched(state="invitation"):
            total_connections += len(connection_batch)
            logger.debug(
                f"Processing batch of {len(connection_batch)} invitation connections"
            )

            for connection in connection_batch:
                # Apply resource limit check
                if processed_connections >= MAX_CONNECTIONS_PER_CLEANUP:
                    cleanup_stats["hit_connection_limit"] = True
                    logger.warning(
                        f"Hit connection processing limit of {MAX_CONNECTIONS_PER_CLEANUP} connections, "
                        f"stopping early (found {total_connections} total)"
                    )
                    break

                processed_connections += 1
                try:

                    # Parse the creation time - ACA-Py uses ISO format
                    created_at_str = connection.get("created_at")
                    if not created_at_str:
                        logger.warning(
                            f"Connection {connection.get('connection_id')} missing created_at timestamp"
                        )
                        continue

                    try:
                        if created_at_str.endswith("Z"):
                            created_at_str = created_at_str[:-1] + "+00:00"
                        connection_time = datetime.fromisoformat(created_at_str)
                        if connection_time.tzinfo is None:
                            connection_time = connection_time.replace(tzinfo=UTC)
                    except ValueError as parse_error:
                        logger.warning(
                            f"Failed to parse timestamp {created_at_str} for connection {connection.get('connection_id')}: {parse_error}"
                        )
                        continue

                    # Check if connection invitation has expired
                    if connection_time < connection_cutoff:
                        connection_id = connection.get("connection_id")
                        logger.debug(
                            f"Cleaning up expired connection invitation {connection_id}"
                        )

                        connection_deleted = client.delete_connection(connection_id)

                        if connection_deleted:
                            cleanup_stats["cleaned_connections"] += 1
                            logger.debug(
                                f"Cleaned up expired connection invitation {connection_id}"
                            )
                        else:
                            cleanup_stats["failed_cleanups"] += 1
                            error_msg = f"Failed to delete expired connection invitation {connection_id}"
                            cleanup_stats["errors"].append(error_msg)
                            logger.warning(error_msg)
                    else:
                        logger.debug(
                            f"Connection invitation {connection.get('connection_id')} is too recent to clean up"
                        )

                except Exception as connection_error:
                    cleanup_stats["failed_cleanups"] += 1
                    error_msg = f"Error processing connection {connection.get('connection_id', 'unknown')}: {connection_error}"
                    cleanup_stats["errors"].append(error_msg)
                    logger.error(error_msg)

            # Break out of batch loop if we hit the limit
            if cleanup_stats["hit_connection_limit"]:
                break

        # Set total connections count after processing all batches
        cleanup_stats["total_connections"] = total_connections
        logger.info(
            f"Processed {processed_connections}/{total_connections} invitation connections"
        )

    except Exception as e:
        error_msg = f"Background cleanup failed: {e}"
        cleanup_stats["errors"].append(error_msg)
        logger.error(error_msg)

    limit_info = ""
    if cleanup_stats["hit_presentation_limit"] or cleanup_stats["hit_connection_limit"]:
        limits_hit = []
        if cleanup_stats["hit_presentation_limit"]:
            limits_hit.append("presentation record limit")
        if cleanup_stats["hit_connection_limit"]:
            limits_hit.append("connection limit")
        limit_info = f" (hit {' and '.join(limits_hit)})"

    logger.info(
        f"Background cleanup completed{limit_info}: "
        f"{cleanup_stats['cleaned_presentation_records']} presentation records cleaned, "
        f"{cleanup_stats['cleaned_connections']} connection invitations cleaned, "
        f"{cleanup_stats['failed_cleanups']} failed out of "
        f"{cleanup_stats['total_presentation_records']} presentation records + "
        f"{cleanup_stats['total_connections']} connections total"
    )
    return cleanup_stats


class PresentationCleanupService:
    """Service for cleaning up old presentation records."""

    def __init__(self):
        self.schedule_minutes = (
            settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES
        )

        # Initialize APScheduler with Redis job store
        self.scheduler = self._create_scheduler()

    def _create_scheduler(self) -> AsyncIOScheduler:
        """Create APScheduler with Redis job store for distributed coordination."""
        # Configure Redis job store
        redis_url = self._build_redis_url()
        jobstore = RedisJobStore(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD if settings.REDIS_PASSWORD else None,
            db=settings.REDIS_DB + 1,  # Use different DB than Socket.IO for job store
        )

        jobstores = {"default": jobstore}

        scheduler = AsyncIOScheduler(jobstores=jobstores)
        logger.info(f"APScheduler initialized with Redis job store at {redis_url}")
        return scheduler

    def _build_redis_url(self) -> str:
        """Build Redis URL for logging purposes."""
        if settings.REDIS_PASSWORD:
            return f"redis://***@{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB + 1}"
        return f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB + 1}"

    def setup_cleanup_job(self):
        """Register the cleanup job with APScheduler."""
        self.scheduler.add_job(
            func=cleanup_old_presentation_records,  # Use standalone function
            trigger=IntervalTrigger(minutes=self.schedule_minutes),
            id="presentation_cleanup",
            max_instances=1,  # Prevent multiple instances running simultaneously
            replace_existing=True,  # Replace job if it already exists
            misfire_grace_time=300,  # 5 minutes grace time for missed jobs
        )
        logger.info(
            f"Cleanup job scheduled - will run every {self.schedule_minutes} minutes"
        )

    async def start_scheduler(self):
        """Start the APScheduler and register cleanup job."""
        try:
            self.setup_cleanup_job()
            self.scheduler.start()
            logger.info("APScheduler started successfully")
        except Exception as e:
            logger.error(f"Failed to start APScheduler: {e}")
            raise

    async def stop_scheduler(self):
        """Gracefully stop the APScheduler."""
        try:
            if self.scheduler.running:
                self.scheduler.shutdown(wait=True)
                logger.info("APScheduler stopped successfully")
        except Exception as e:
            logger.error(f"Error stopping APScheduler: {e}")


# Global instance for the cleanup service
cleanup_service = PresentationCleanupService()
