from pydantic import BaseModel, ConfigDict, Field


class ServiceDecorator(BaseModel, frozen=True):
    # https://github.com/hyperledger/aries-rfcs/tree/main/features/0056-service-decorator
    recipient_keys: list[str] | None = Field(default=None, alias="recipientKeys")
    routing_keys: list[str] | None = Field(default=None, alias="routingKeys")
    service_endpoint: str | None = Field(default=None, alias="serviceEndpoint")

    model_config = ConfigDict(populate_by_name=True)


class OOBServiceDecorator(ServiceDecorator, frozen=True):
    # ServiceDecorator
    recipient_keys: list[str] | None = Field(default=None, alias="recipientKeys")
    routing_keys: list[str] | None = Field(default=None, alias="routingKeys")
    service_endpoint: str | None = Field(default=None, alias="serviceEndpoint")
    id: str = Field(
        default="did:acapy-vc-authn-oidc:123456789zyxwvutsr#did-communication"
    )
    type: str = Field(default="did-communication")
    priority: int = 0

    model_config = ConfigDict(populate_by_name=True)
