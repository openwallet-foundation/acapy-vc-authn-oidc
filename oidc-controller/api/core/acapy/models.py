from typing import Any

from ..models import FrozenModel
from . import OutOfBandMessage


class WalletDid(FrozenModel):
    did: str
    verkey: str
    posture: str


class WalletDidPublicResponse(FrozenModel):
    result: WalletDid | None = None


class CreatePresentationResponse(FrozenModel):
    thread_id: str
    pres_ex_id: str
    pres_request: dict[str, Any]


class OobCreateInvitationResponse(FrozenModel):
    invi_msg_id: str
    invitation_url: str
    oob_id: str
    trace: bool
    state: str
    invitation: OutOfBandMessage
