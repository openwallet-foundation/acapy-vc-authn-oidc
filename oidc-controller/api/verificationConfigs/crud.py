from fastapi.encoders import jsonable_encoder
from pymongo import ReturnDocument
from pymongo.database import Database

from ..core.http_exception_util import (
    check_and_raise_not_found_http_exception,
    raise_appropriate_http_exception,
)
from ..db.session import COLLECTION_NAMES
from .models import (
    VerificationConfig,
    VerificationConfigPatch,
)

NOT_FOUND_MSG = "The requested verifier configuration wasn't found"


class VerificationConfigCRUD:
    _db: Database

    def __init__(self, db: Database):
        self._db = db

    async def create(self, ver_config: VerificationConfig) -> VerificationConfig:
        ver_confs = self._db.get_collection(COLLECTION_NAMES.VER_CONFIGS)

        try:
            ver_confs.insert_one(jsonable_encoder(ver_config))
        except Exception as err:
            raise_appropriate_http_exception(
                err, exists_msg="Verifier configuration already exists"
            )
        return ver_confs.find_one({"ver_config_id": ver_config.ver_config_id})

    async def get(self, ver_config_id: str) -> VerificationConfig:
        ver_confs = self._db.get_collection(COLLECTION_NAMES.VER_CONFIGS)
        ver_conf = ver_confs.find_one({"ver_config_id": ver_config_id})
        check_and_raise_not_found_http_exception(ver_conf, NOT_FOUND_MSG)

        return VerificationConfig(**ver_conf)

    async def get_all(self) -> list[VerificationConfig]:
        ver_confs = self._db.get_collection(COLLECTION_NAMES.VER_CONFIGS)
        return [VerificationConfig(**vc) for vc in ver_confs.find()]

    async def patch(
        self, ver_config_id: str, data: VerificationConfigPatch
    ) -> VerificationConfig:
        if not isinstance(data, VerificationConfigPatch):
            raise Exception("please provide an instance of the <document> PATCH class")
        ver_confs = self._db.get_collection(COLLECTION_NAMES.VER_CONFIGS)
        ver_conf = ver_confs.find_one_and_update(
            {"ver_config_id": ver_config_id},
            {"$set": data.model_dump(exclude_unset=True)},
            return_document=ReturnDocument.AFTER,
        )
        check_and_raise_not_found_http_exception(ver_conf, NOT_FOUND_MSG)

        return ver_conf

    async def delete(self, ver_config_id: str) -> bool:
        ver_confs = self._db.get_collection(COLLECTION_NAMES.VER_CONFIGS)
        ver_conf = ver_confs.find_one_and_delete({"ver_config_id": ver_config_id})
        check_and_raise_not_found_http_exception(ver_conf, NOT_FOUND_MSG)
        return bool(ver_conf)
