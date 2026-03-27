import base64
import json

from pydantic import BaseModel, ConfigDict, Field

from api.core.acapy import PresentProofv20Attachment, ServiceDecorator


class PresentationRequestMessage(BaseModel):
    # https://github.com/hyperledger/aries-rfcs/blob/main/features/0037-present-proof/README.md#presentation
    id: str = Field(alias="@id")
    type: str = Field(
        "https://didcomm.org/present-proof/2.0/request-presentation",
        alias="@type",
    )
    formats: list[dict]
    request: list[PresentProofv20Attachment] = Field(
        alias="request_presentations~attach"
    )
    comment: str | None = None
    service: ServiceDecorator | None = Field(None, alias="~service")

    model_config = ConfigDict(populate_by_name=True)

    def b64_str(self):
        # object->dict->jsonString->ascii->ENCODE->ascii
        return base64.b64encode(
            json.dumps(self.model_dump(by_alias=True)).encode("ascii")
        ).decode("ascii")
