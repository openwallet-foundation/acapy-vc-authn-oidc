from pydantic import BaseModel

from . import OutOfBandMessage


class WalletDid(BaseModel):
    did: str
    verkey: str
    posture: str


class WalletDidPublicResponse(BaseModel):
    result: WalletDid | None = None


class CreatePresentationResponse(BaseModel):
    thread_id: str
    pres_ex_id: str
    pres_request: dict


class OobCreateInvitationResponse(BaseModel):
    invi_msg_id: str
    invitation_url: str
    oob_id: str
    trace: bool
    state: str
    invitation: OutOfBandMessage
