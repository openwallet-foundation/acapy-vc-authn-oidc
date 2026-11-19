from typing import Any

from pydantic import BaseModel

from . import OutOfBandMessage


class WalletDid(BaseModel, frozen=True):
    did: str
    verkey: str
    posture: str


class WalletDidPublicResponse(BaseModel, frozen=True):
    result: WalletDid | None = None


class CreatePresentationResponse(BaseModel, frozen=True):
    thread_id: str
    pres_ex_id: str
    pres_request: dict[str, Any]


class OobCreateInvitationResponse(BaseModel, frozen=True):
    invi_msg_id: str
    invitation_url: str
    oob_id: str
    trace: bool
    state: str
    invitation: OutOfBandMessage
