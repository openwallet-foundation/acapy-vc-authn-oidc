from datetime import datetime, timedelta
from enum import StrEnum, auto

from api.core.models import UUIDModel
from pydantic import BaseModel, ConfigDict, Field

from ..core.config import settings


class AuthSessionState(StrEnum):
    NOT_STARTED = auto()
    PENDING = auto()
    EXPIRED = auto()
    VERIFIED = auto()
    FAILED = auto()
    REVOKED = auto()
    ABANDONED = auto()


class AuthSessionBase(BaseModel):
    pres_exch_id: str
    expired_timestamp: datetime = Field(
        default=datetime.now()
        + timedelta(seconds=settings.CONTROLLER_PRESENTATION_EXPIRE_TIME)
    )
    ver_config_id: str
    request_parameters: dict
    pyop_auth_code: str
    response_url: str
    presentation_request_msg: dict | None = None
    model_config = ConfigDict(populate_by_name=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuthSession(AuthSessionBase, UUIDModel):
    proof_status: AuthSessionState = Field(default=AuthSessionState.NOT_STARTED)
    presentation_exchange: dict | None = Field(default_factory=dict)


class AuthSessionCreate(AuthSessionBase):
    pass


class AuthSessionPatch(AuthSessionBase):
    proof_status: AuthSessionState = Field(default=AuthSessionState.PENDING)
    presentation_exchange: dict = Field(default_factory=dict)
    pass
