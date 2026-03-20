import structlog

from fastapi import APIRouter
from fastapi.responses import JSONResponse

# from oic.oauth2.message import ASConfigurationResponse
from ..core.oidc import provider

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

router = APIRouter()


@router.get("/.well-known/openid-configuration", response_class=JSONResponse)
async def get_well_known_oid_config():
    """returns configuration response compliant with
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
    """
    return provider.configuration_information


@router.get("/.well-known/openid-configuration/jwks", response_class=JSONResponse)
async def get_well_known_jwks():
    return {"keys": [provider.signing_key.serialize(private=False)]}
