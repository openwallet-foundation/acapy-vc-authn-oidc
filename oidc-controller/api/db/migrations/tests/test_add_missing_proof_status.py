"""Tests for add_missing_proof_status migration."""

from unittest.mock import MagicMock, patch

from api.authSessions.models import AuthSessionState
from api.db.migrations.add_missing_proof_status import migrate_missing_proof_status


def make_mock_db(count_without_status, modified_count):
    """Build a mock MongoClient hierarchy for the migration."""
    mock_col = MagicMock()
    mock_col.count_documents.side_effect = [count_without_status, 0]
    mock_result = MagicMock()
    mock_result.modified_count = modified_count
    mock_result.matched_count = modified_count
    mock_col.update_many.return_value = mock_result

    mock_db = MagicMock()
    mock_db.get_collection.return_value = mock_col

    mock_client = MagicMock()
    mock_client.__getitem__.return_value = mock_db
    return mock_client, mock_col


@patch("api.db.migrations.add_missing_proof_status.MongoClient")
def test_migrate_no_documents_to_fix(mock_mongo):
    mock_client, mock_col = make_mock_db(count_without_status=0, modified_count=0)
    mock_client.count_documents = mock_col.count_documents
    mock_mongo.return_value = mock_client

    result = migrate_missing_proof_status()

    assert result == 0
    mock_col.update_many.assert_not_called()


@patch("api.db.migrations.add_missing_proof_status.MongoClient")
def test_migrate_updates_documents(mock_mongo):
    mock_client, mock_col = make_mock_db(count_without_status=5, modified_count=5)
    mock_mongo.return_value = mock_client

    result = migrate_missing_proof_status()

    assert result == 5
    mock_col.update_many.assert_called_once_with(
        {"proof_status": {"$exists": False}},
        {"$set": {"proof_status": AuthSessionState.NOT_STARTED}},
    )
    mock_client.close.assert_called_once()


@patch("api.db.migrations.add_missing_proof_status.MongoClient")
def test_migrate_remaining_documents_warning(mock_mongo):
    """Covers the warning branch when some docs still lack proof_status after migration."""
    mock_client, mock_col = make_mock_db(count_without_status=3, modified_count=2)
    # Override second count_documents call to return non-zero (remaining docs)
    mock_col.count_documents.side_effect = [3, 1]
    mock_mongo.return_value = mock_client

    result = migrate_missing_proof_status()

    assert result == 2
