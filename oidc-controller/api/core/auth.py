from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from .config import settings

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)
API_KEY = settings.CONTROLLER_API_KEY


async def get_api_key(api_key_header: str = Security(api_key_header)):
    if not API_KEY or api_key_header == API_KEY:
        return api_key_header
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate x-api-key",
        )
