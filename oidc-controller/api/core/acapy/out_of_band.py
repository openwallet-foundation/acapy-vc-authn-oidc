from pydantic import BaseModel, ConfigDict, Field

from .service_decorator import OOBServiceDecorator


class OutOfBandPresentProofAttachment(BaseModel):
    id: str = Field(alias="@id")
    mime_type: str = Field(default="application/json", alias="mime-type")
    data: dict

    model_config = ConfigDict(populate_by_name=True)


class OutOfBandMessage(BaseModel):
    # https://github.com/hyperledger/aries-rfcs/blob/main/features/0434-outofband
    id: str = Field(alias="@id")
    type: str = Field(
        default="https://didcomm.org/out-of-band/1.1/invitation",
        alias="@type",
    )
    goal_code: str = Field(default="aries.vc.verifier.once")
    label: str = Field(
        default="acapy-vc-authn Out-of-Band present-proof authorization request"
    )
    request_attachments: list[OutOfBandPresentProofAttachment] | None = Field(
        alias="requests~attach", default=None
    )
    services: list[OOBServiceDecorator | str] = Field(alias="services")
    handshake_protocols: list[str] | None = Field(alias="handshake_protocols", default=None)

    model_config = ConfigDict(populate_by_name=True)
