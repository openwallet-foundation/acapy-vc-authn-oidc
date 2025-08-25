"""Background cleanup service for presentation records."""

import asyncio
from datetime import datetime, timedelta, UTC
from typing import List

import structlog

from ..core.config import settings
from ..core.acapy.client import AcapyClient

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


class PresentationCleanupService:
    """Service for cleaning up old presentation records."""

    def __init__(self):
        self.client = AcapyClient()
        self.retention_hours = settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS
        self.schedule_minutes = settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES

    async def cleanup_old_presentation_records(self) -> dict:
        """Clean up presentation records older than retention period."""
        logger.info("Starting background cleanup of old presentation records")

        cutoff_time = datetime.now(UTC) - timedelta(hours=self.retention_hours)
        cleanup_stats = {
            "total_records": 0,
            "cleaned_records": 0,
            "failed_cleanups": 0,
            "errors": [],
        }

        try:
            # Get all presentation records
            records = self.client.get_all_presentation_records()
            cleanup_stats["total_records"] = len(records)

            logger.info(
                f"Found {len(records)} presentation records for cleanup evaluation"
            )

            for record in records:
                try:
                    # Parse the creation time - ACA-Py uses ISO format
                    created_at_str = record.get("created_at")
                    if not created_at_str:
                        logger.warning(
                            f"Record {record.get('pres_ex_id')} has no created_at timestamp, skipping"
                        )
                        continue

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
                    if record_time < cutoff_time:
                        pres_ex_id = record.get("pres_ex_id")
                        success = self.client.delete_presentation_record(pres_ex_id)

                        if success:
                            cleanup_stats["cleaned_records"] += 1
                            logger.debug(
                                f"Cleaned up old presentation record {pres_ex_id}"
                            )
                        else:
                            cleanup_stats["failed_cleanups"] += 1
                            error_msg = (
                                f"Failed to delete presentation record {pres_ex_id}"
                            )
                            cleanup_stats["errors"].append(error_msg)
                            logger.warning(error_msg)
                    else:
                        logger.debug(
                            f"Record {record.get('pres_ex_id')} is too recent to clean up"
                        )

                except Exception as record_error:
                    cleanup_stats["failed_cleanups"] += 1
                    error_msg = f"Error processing record {record.get('pres_ex_id', 'unknown')}: {record_error}"
                    cleanup_stats["errors"].append(error_msg)
                    logger.error(error_msg)

        except Exception as e:
            error_msg = f"Background cleanup failed: {e}"
            cleanup_stats["errors"].append(error_msg)
            logger.error(error_msg)

        logger.info(
            f"Background cleanup completed: {cleanup_stats['cleaned_records']} cleaned, "
            f"{cleanup_stats['failed_cleanups']} failed out of {cleanup_stats['total_records']} total records"
        )

        return cleanup_stats

    async def start_background_cleanup_task(self):
        """Start the periodic background cleanup task."""
        logger.info(
            f"Starting background cleanup task - will run every {self.schedule_minutes} minutes"
        )

        while True:
            try:
                await self.cleanup_old_presentation_records()

                # Sleep for the configured interval
                sleep_seconds = self.schedule_minutes * 60
                logger.debug(f"Background cleanup sleeping for {sleep_seconds} seconds")
                await asyncio.sleep(sleep_seconds)

            except Exception as e:
                logger.error(f"Background cleanup task encountered an error: {e}")
                # Sleep for a shorter period on error to retry sooner
                await asyncio.sleep(300)  # 5 minutes on error


# Global instance for the cleanup service
cleanup_service = PresentationCleanupService()
