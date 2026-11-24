from typing import Any

import structlog
from fastapi import HTTPException
from fastapi import status as http_status
from pymongo import ReturnDocument
from pymongo.database import Database

from api.db.session import COLLECTION_NAMES

from ..core.auth_session import Event, Rejected, apply
from ..core.models import PyObjectId
from .models import AuthSession, AuthSessionCreate, AuthSessionPatch, AuthSessionState

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

# The status only moves forward (NOT_STARTED -> PENDING -> a final state), so
# it can change under us at most twice: one initial attempt plus two retries.
MAX_ADVANCE_ATTEMPTS = 3


def _changed_fields(before: AuthSession, after: AuthSession) -> dict[str, Any]:
    before_fields = before.model_dump()
    return {
        key: value
        for key, value in after.model_dump().items()
        if value != before_fields[key]
    }


class AuthSessionCRUD:
    def __init__(self, db: Database):
        self._db = db

    async def create(self, auth_session: AuthSessionCreate) -> AuthSession:
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        result = col.insert_one(auth_session.model_dump())
        return AuthSession.model_validate(col.find_one({"_id": result.inserted_id}))

    async def get_by_connection_id(self, connection_id: str) -> AuthSession | None:
        """Get auth session by connection ID for connection-based verification."""
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        result = col.find_one({"connection_id": connection_id})
        return AuthSession(**result) if result else None

    async def get(self, id: str) -> AuthSession:
        if not PyObjectId.is_valid(id):
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST, detail=f"Invalid id: {id}"
            )
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        auth_sess = col.find_one({"_id": PyObjectId(id)})

        if auth_sess is None:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail="The auth_session hasn't been found!",
            )

        return AuthSession(**auth_sess)

    async def patch(
        self, id: str | PyObjectId, data: AuthSessionPatch
    ) -> AuthSession | None:
        if not PyObjectId.is_valid(id):
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST, detail=f"Invalid id: {id}"
            )
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        auth_sess = col.find_one_and_update(
            {"_id": PyObjectId(id)},
            {"$set": data.model_dump(exclude_unset=True)},
            return_document=ReturnDocument.AFTER,
        )

        return AuthSession.model_validate(auth_sess) if auth_sess else None

    async def advance(
        self, session: AuthSession, event: Event
    ) -> AuthSession | Rejected:
        """Apply EVENT to SESSION and save the result.

        The write only goes through if the stored status is still the one the
        event was applied to. If another writer changed it first, the event is
        applied again to the stored session, so a webhook that loaded the
        session just before a scan marked it pending is still saved. Only the
        fields the event changed are written.

        Returns the saved session, or Rejected if the event is not legal in the
        stored state or the session is gone; the caller should then skip the
        event's side effects.
        """
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        log = logger.bind(
            auth_session_id=str(session.id), event_type=type(event).__name__
        )
        for _ in range(MAX_ADVANCE_ATTEMPTS):
            after = apply(session, event)
            if isinstance(after, Rejected):
                log.debug("Auth session event rejected", reason=after.reason)
                return after

            saved = self._save_if_status_unchanged(session, after)
            if saved is not None:
                return saved

            log.info("Auth session changed concurrently, reapplying event")
            if (stored := col.find_one({"_id": PyObjectId(session.id)})) is None:
                return Rejected("session is gone")
            session = AuthSession.model_validate(stored)

        log.warning("Auth session kept changing, ignoring event")
        return Rejected("session kept changing")

    def _save_if_status_unchanged(
        self, before: AuthSession, after: AuthSession
    ) -> AuthSession | None:
        """Write the fields that differ between BEFORE and AFTER, but only if
        the stored proof_status still equals BEFORE's.

        Returns the stored session, or None if the status has changed or the
        session is gone.
        """
        changes = _changed_fields(before, after)
        expected: object = before.proof_status
        if before.proof_status is AuthSessionState.NOT_STARTED:
            # Records created before proof_status existed have no field;
            # AuthSession reads them as NOT_STARTED.
            expected = {"$in": [AuthSessionState.NOT_STARTED, None]}
        query = {"_id": PyObjectId(before.id), "proof_status": expected}
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        # An empty $set is a no-op on MongoDB 5.0 and later, but the status
        # check still applies.
        saved = col.find_one_and_update(
            query, {"$set": changes}, return_document=ReturnDocument.AFTER
        )
        return AuthSession.model_validate(saved) if saved is not None else None

    async def delete(self, id: str) -> bool:
        if not PyObjectId.is_valid(id):
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST, detail=f"Invalid id: {id}"
            )
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        auth_sess = col.find_one_and_delete({"_id": PyObjectId(id)})
        return bool(auth_sess)

    async def get_by_pres_exch_id(self, pres_exch_id: str) -> AuthSession:
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        auth_sess = col.find_one({"pres_exch_id": pres_exch_id})

        if auth_sess is None:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail="The auth_session hasn't been found with that pres_exch_id!",
            )

        return AuthSession(**auth_sess)

    async def get_by_pyop_auth_code(self, code: str) -> AuthSession:
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        auth_sess = col.find_one({"pyop_auth_code": code})

        if auth_sess is None:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail="The auth_session hasn't been found with that pyop_auth_code!",
            )

        return AuthSession(**auth_sess)

    async def claim_auth_code(self, code: str) -> bool:
        """Atomically mark a verified session's authorization code as redeemed.

        A single find_one_and_update lets exactly one concurrent caller win, so a
        code can be exchanged at most once across all pods. Returns False if the
        code is unknown, the proof is not VERIFIED, or it was already redeemed.
        """
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        claimed = col.find_one_and_update(
            {
                "pyop_auth_code": code,
                "proof_status": AuthSessionState.VERIFIED,
                "code_redeemed": {"$ne": True},
            },
            {"$set": {"code_redeemed": True}},
        )
        return claimed is not None

    async def update_pyop_auth_code(
        self, id: str | PyObjectId, pyop_auth_code: str
    ) -> bool:
        """Update only the pyop_auth_code field for authorization code regeneration."""
        if not PyObjectId.is_valid(id):
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST, detail=f"Invalid id: {id}"
            )
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        result = col.update_one(
            {"_id": PyObjectId(id)}, {"$set": {"pyop_auth_code": pyop_auth_code}}
        )
        return result.modified_count > 0

    async def update_pyop_user_id(
        self, id: str | PyObjectId, pyop_user_id: str
    ) -> bool:
        """Update the pyop_user_id field when subject is replaced."""
        if not PyObjectId.is_valid(id):
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid id: {id}",
            )
        col = self._db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        result = col.update_one(
            {"_id": PyObjectId(id)},
            {"$set": {"pyop_user_id": pyop_user_id}},
        )
        return result.modified_count > 0
