from typing import Any

from pydantic import BaseModel, Field


class PresentProofv20Attachment(BaseModel, frozen=True):
    # https://github.com/hyperledger/aries-rfcs/tree/eace815c3e8598d4a8dd7881d8c731fdb2bcc0aa/features/0454-present-proof-v2
    id: str = Field(default="libindy-request-presentation-0", alias="@id")
    mime_type: str = Field(default="application/json", alias="mime-type")
    data: dict[str, Any]
