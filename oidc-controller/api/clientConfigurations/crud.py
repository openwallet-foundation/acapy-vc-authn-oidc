import structlog

from pymongo import ReturnDocument
from pymongo.database import Database
from fastapi.encoders import jsonable_encoder

from ..core.http_exception_util import (
    raise_appropriate_http_exception,
    check_and_raise_not_found_http_exception,
)
from ..db.session import COLLECTION_NAMES

from .models import (
    ClientConfiguration,
    ClientConfigurationPatch,
)

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

NOT_FOUND_MSG = "The requested client configuration wasn't found"


class ClientConfigurationCRUD:
    def __init__(self, db: Database):
        self._db = db

    async def create(self, client_config: ClientConfiguration) -> ClientConfiguration:
        col = self._db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS)
        try:
            col.insert_one(jsonable_encoder(client_config))
        except Exception as err:
            raise_appropriate_http_exception(
                err, exists_msg="Client configuration already exists"
            )

        # No need to reload provider - DynamicClientDatabase loads from MongoDB on-demand
        return ClientConfiguration(
            **col.find_one({"client_id": client_config.client_id})
        )

    async def get(self, client_id: str) -> ClientConfiguration:
        col = self._db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS)
        obj = col.find_one({"client_id": client_id})
        check_and_raise_not_found_http_exception(obj, NOT_FOUND_MSG)

        return ClientConfiguration(**obj)

    async def get_all(self) -> list[ClientConfiguration]:
        col = self._db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS)
        return [ClientConfiguration(**cc) for cc in col.find()]

    async def patch(
        self, client_id: str, data: ClientConfigurationPatch
    ) -> ClientConfiguration:
        col = self._db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS)
        obj = col.find_one_and_update(
            {"client_id": client_id},
            {"$set": data.model_dump(exclude_unset=True)},
            return_document=ReturnDocument.AFTER,
        )
        check_and_raise_not_found_http_exception(obj, NOT_FOUND_MSG)

        # No need to reload provider - DynamicClientDatabase loads from MongoDB on-demand
        return obj

    async def delete(self, client_id: str) -> bool:
        col = self._db.get_collection(COLLECTION_NAMES.CLIENT_CONFIGURATIONS)
        obj = col.find_one_and_delete({"client_id": client_id})
        check_and_raise_not_found_http_exception(obj, NOT_FOUND_MSG)

        # No need to reload provider - DynamicClientDatabase loads from MongoDB on-demand
        return bool(obj)
