import structlog
from fastapi import HTTPException
from fastapi import status as http_status
from pymongo.errors import WriteError

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

CONFLICT_DEFAULT_MSG = "The requested resource already exists"
NOT_FOUND_DEFAULT_MSG = "The requested resource wasn't found"
UNKNOWN_DEFAULT_MSG = "The server was unable to process the request"


def raise_appropriate_http_exception(
    err: WriteError, exists_msg: str = CONFLICT_DEFAULT_MSG
):
    if err.code == 11000:
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail=exists_msg,
        )
    else:
        logger.error("Unknown error", err=err)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=UNKNOWN_DEFAULT_MSG,
        )


def check_and_raise_not_found_http_exception(resp, detail: str = NOT_FOUND_DEFAULT_MSG):
    if resp is None:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=detail,
        )
