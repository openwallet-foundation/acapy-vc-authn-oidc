"""
HTTP routes for cleanup operations.

This module provides RESTful HTTP endpoints for managing the cleanup of old presentation
records and expired connection invitations in the VC-AuthN OIDC system.

The cleanup system was migrated from APScheduler to HTTP endpoints for better Kubernetes
integration, operational control, and multi-pod compatibility.

Endpoints:
    DELETE /cleanup - Main cleanup operation with optional query parameters
    GET /health - Health check endpoint for monitoring

Authentication:
    All cleanup endpoints (except health) require authentication via X-API-Key header
    using the same controller API key used for other system endpoints.

Example Usage:
    # Basic cleanup
    curl -X DELETE "http://controller/cleanup" -H "X-API-Key: your-key"

    # Dry run (preview what would be deleted)
    curl -X DELETE "http://controller/cleanup?dry_run=true" -H "X-API-Key: your-key"

    # Custom resource limits
    curl -X DELETE "http://controller/cleanup?max_records=500&max_connections=1000" \
         -H "X-API-Key: your-key"

Response Format:
    All endpoints return JSON responses with detailed statistics and status information.
    The main cleanup endpoint provides comprehensive metrics about the cleanup operation.

Production Deployment:
    - Typically called by Kubernetes CronJob for automated scheduling
    - Can be called manually for troubleshooting or emergency cleanup
    - Supports dry-run mode for safe testing in production
    - Resource limits prevent excessive processing and DoS protection
"""

import structlog
from datetime import datetime

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional

from ..core.auth import get_api_key
from ..services.cleanup import (
    perform_cleanup,
    validate_cleanup_configuration,
)

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

# Validate cleanup configuration at router initialization
validate_cleanup_configuration()

router = APIRouter()


@router.delete("/cleanup", dependencies=[Depends(get_api_key)])
async def cleanup_endpoint(
    dry_run: bool = Query(
        False, description="Preview what would be deleted without actually deleting"
    ),
    max_records: Optional[int] = Query(
        None, description="Override max presentation records limit"
    ),
    max_connections: Optional[int] = Query(
        None, description="Override max connections limit"
    ),
) -> JSONResponse:
    """
    Perform cleanup of old presentation records and expired connections.

    This endpoint removes old presentation records and expired connection invitations
    to maintain system performance and prevent database growth. It implements resource
    limits to prevent DoS and provides dry-run capability for safe testing.

    The cleanup operation processes:
    - Presentation records older than CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS
    - Connection invitations in "invitation" state older than CONTROLLER_PRESENTATION_EXPIRE_TIME

    Authentication: Requires X-API-Key header with controller API key.
    Designed for: Kubernetes CronJob scheduling or manual operations.

    Args:
        dry_run (bool): If True, only report what would be deleted without actual deletion.
                       Useful for testing and validation in production environments.
        max_records (int, optional): Override default max presentation records to process.
                                   Prevents excessive resource usage on large datasets.
        max_connections (int, optional): Override default max connections to process.
                                       Provides granular control over cleanup scope.

    Returns:
        JSONResponse: Detailed cleanup statistics including:
            - status: Operation completion status
            - timestamp: Operation execution time
            - statistics: Comprehensive metrics (total, cleaned, failed counts)
            - has_errors: Boolean indicating if any errors occurred

    Raises:
        HTTPException: 401/403 for authentication failures, 500 for internal errors.

    Example Response:
        {
            "status": "completed",
            "timestamp": "2024-01-01T02:00:00.000Z",
            "statistics": {
                "total_presentation_records": 150,
                "cleaned_presentation_records": 45,
                "total_connections": 75,
                "cleaned_connections": 12,
                "failed_cleanups": 0,
                "hit_presentation_limit": false,
                "hit_connection_limit": false,
                "error_count": 0
            },
            "has_errors": false
        }
    """
    try:
        logger.info("Cleanup triggered via HTTP endpoint", dry_run=dry_run)

        # Execute the cleanup
        stats = await perform_cleanup(
            dry_run=dry_run,
            max_presentation_records=max_records,
            max_connections=max_connections,
        )

        # Prepare response data
        response_data = {
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": {
                "total_presentation_records": stats["total_presentation_records"],
                "cleaned_presentation_records": stats["cleaned_presentation_records"],
                "total_connections": stats["total_connections"],
                "cleaned_connections": stats["cleaned_connections"],
                "failed_cleanups": stats["failed_cleanups"],
                "hit_presentation_limit": stats["hit_presentation_limit"],
                "hit_connection_limit": stats["hit_connection_limit"],
                "error_count": len(stats["errors"]),
            },
        }

        # Include errors if any (but don't expose sensitive details)
        if stats["errors"]:
            response_data["has_errors"] = True
            logger.warning(
                "Cleanup completed with errors",
                error_count=len(stats["errors"]),
                errors=stats["errors"],
            )
        else:
            response_data["has_errors"] = False

        logger.info(
            "Cleanup completed successfully via HTTP endpoint",
            cleaned_presentations=stats["cleaned_presentation_records"],
            cleaned_connections=stats["cleaned_connections"],
            failed_cleanups=stats["failed_cleanups"],
        )

        return JSONResponse(status_code=200, content=response_data)

    except Exception as e:
        logger.error(
            "Cleanup operation failed via HTTP endpoint",
            error=str(e),
            error_type=type(e).__name__,
        )

        raise HTTPException(
            status_code=500, detail="Internal server error during cleanup operation"
        )


@router.get("/health")
async def cleanup_health_check():
    """Health check endpoint for cleanup service."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": "cleanup",
            "timestamp": datetime.utcnow().isoformat(),
        },
    )
