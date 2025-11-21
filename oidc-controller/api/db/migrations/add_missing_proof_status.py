"""
Migration script to add missing proof_status field to existing AuthSession documents.

This script fixes documents that were created before the proof_status field was
properly initialized, which prevents them from being cleaned up by the TTL index.

Run this script once to fix existing documents:
    python -m api.db.migrations.add_missing_proof_status
"""

import structlog
from api.authSessions.models import AuthSessionState
from api.core.config import settings
from api.db.collections import COLLECTION_NAMES
from pymongo import MongoClient

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


def migrate_missing_proof_status():
    """
    Add proof_status field to AuthSession documents that are missing it.

    Sets proof_status to NOT_STARTED for documents without the field.
    """
    client = MongoClient(settings.MONGODB_URL, uuidRepresentation="standard")
    db = client[settings.DB_NAME]
    col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)

    # Find documents without proof_status field
    query = {"proof_status": {"$exists": False}}
    documents_without_status = col.count_documents(query)

    if documents_without_status == 0:
        logger.info("No documents found missing proof_status field")
        return 0

    logger.info(
        f"Found {documents_without_status} documents missing proof_status field"
    )

    # Update all documents without proof_status
    result = col.update_many(
        query, {"$set": {"proof_status": AuthSessionState.NOT_STARTED}}
    )

    logger.info(
        f"Updated {result.modified_count} documents with proof_status",
        matched=result.matched_count,
        modified=result.modified_count,
    )

    # Verify the fix
    remaining = col.count_documents({"proof_status": {"$exists": False}})
    if remaining > 0:
        logger.warning(
            f"Still {remaining} documents without proof_status after migration"
        )
    else:
        logger.info("All documents now have proof_status field")

    client.close()
    return result.modified_count


if __name__ == "__main__":
    try:
        modified_count = migrate_missing_proof_status()
        print(f"Migration complete. Updated {modified_count} documents.")
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise
