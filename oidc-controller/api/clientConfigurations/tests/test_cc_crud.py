import pytest

from api.clientConfigurations.crud import ClientConfigurationCRUD
from api.clientConfigurations.models import (
    ClientConfiguration,
    ClientConfigurationPatch,
)

from api.db.session import COLLECTION_NAMES

from mongomock import MongoClient
from typing import Callable
import structlog

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)


def test_answer():
    assert True


test_client_config = ClientConfiguration(
    client_id="test_client",
    client_name="test_client_name",
    client_secret="test_client_secret",
    redirect_uris=["http://redirecturi.com"],
)


@pytest.mark.asyncio
async def test_client_config_get(db_client: Callable[[], MongoClient]):
    client = db_client()
    crud = ClientConfigurationCRUD(client.db)

    client.db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS).insert_one(
        test_client_config.model_dump()
    )

    result = await crud.get(test_client_config.client_id)
    assert result


@pytest.mark.asyncio
async def test_client_config_create(db_client: Callable[[], MongoClient]):
    client = db_client()
    crud = ClientConfigurationCRUD(client.db)

    await crud.create(test_client_config)
    document = client.db.get_collection(
        COLLECTION_NAMES.CLIENT_CONFIGURATIONS
    ).find_one({"client_id": test_client_config.client_id})
    assert document


@pytest.mark.asyncio
async def test_client_config_delete(db_client: Callable[[], MongoClient]):
    client = db_client()
    crud = ClientConfigurationCRUD(client.db)

    client.db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS).insert_one(
        test_client_config.model_dump()
    )

    result = await crud.delete(test_client_config.client_id)
    assert result

    document = client.db.get_collection(
        COLLECTION_NAMES.CLIENT_CONFIGURATIONS
    ).find_one({"client_id": test_client_config.client_id})
    assert not document


@pytest.fixture(name="log_output")
def fixture_log_output():
    return structlog.testing.LogCapture()


@pytest.fixture(autouse=True)
def fixture_configure_structlog(log_output):
    structlog.configure(processors=[log_output])


@pytest.mark.asyncio
async def test_client_config_patch(db_client: Callable[[], MongoClient], log_output):
    client = db_client()
    crud = ClientConfigurationCRUD(client.db)

    client.db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS).insert_one(
        test_client_config.model_dump()
    )

    assert log_output.entries == []

    result = await crud.patch(
        test_client_config.client_id,
        ClientConfigurationPatch(client_secret="patched_client_secret"),
    )
    assert result
    document = client.db.get_collection(
        COLLECTION_NAMES.CLIENT_CONFIGURATIONS
    ).find_one({"client_id": test_client_config.client_id})
    assert document["client_secret"] == "patched_client_secret"


@pytest.mark.asyncio
async def test_client_config_get_all(db_client: Callable[[], MongoClient]):
    """Test that get_all() returns all client configurations."""
    client = db_client()
    crud = ClientConfigurationCRUD(client.db)

    # Insert multiple client configurations
    client1 = ClientConfiguration(
        client_id="client1",
        client_name="Client 1",
        client_secret="secret1",
        redirect_uris=["http://redirect1.com"],
    )
    client2 = ClientConfiguration(
        client_id="client2",
        client_name="Client 2",
        client_secret="secret2",
        redirect_uris=["http://redirect2.com"],
    )

    client.db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS).insert_one(
        client1.model_dump()
    )
    client.db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS).insert_one(
        client2.model_dump()
    )

    # Get all client configurations
    result = await crud.get_all()

    # Verify all clients are returned
    assert len(result) == 2
    client_ids = [c.client_id for c in result]
    assert "client1" in client_ids
    assert "client2" in client_ids
