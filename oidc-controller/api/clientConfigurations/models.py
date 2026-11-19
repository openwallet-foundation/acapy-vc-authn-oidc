from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from ..core.config import settings
from .examples import ex_client_config


class TOKENENDPOINTAUTHMETHODS(StrEnum):
    client_secret_basic = "client_secret_basic"
    client_secret_post = "client_secret_post"

    @classmethod
    def list(cls):
        return [c.value for c in cls]


class ClientConfigurationBase(BaseModel, frozen=True):
    client_id: str = Field(default=settings.OIDC_CLIENT_ID)
    client_name: str = Field(default=settings.OIDC_CLIENT_NAME)
    response_types: list[str] = Field(default=["code", "id_token", "token"])
    redirect_uris: list[str]
    token_endpoint_auth_method: TOKENENDPOINTAUTHMETHODS = Field(
        default=TOKENENDPOINTAUTHMETHODS.client_secret_basic
    )

    client_secret: str = Field(default=settings.OIDC_CLIENT_SECRET)

    model_config = ConfigDict(
        populate_by_name=True, json_schema_extra={"example": ex_client_config}
    )


class ClientConfiguration(ClientConfigurationBase, frozen=True):
    pass


class ClientConfigurationRead(ClientConfigurationBase, frozen=True):
    pass


class ClientConfigurationPatch(BaseModel, frozen=True):
    client_id: str | None = None
    client_name: str | None = None
    response_types: list[str] | None = None
    redirect_uris: list[str] | None = None
    token_endpoint_auth_method: TOKENENDPOINTAUTHMETHODS | None = None
    client_secret: str | None = None

    model_config = ClientConfigurationBase.model_config
