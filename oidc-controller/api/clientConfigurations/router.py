from fastapi import APIRouter, Depends
from fastapi import status as http_status
from pymongo.database import Database

from ..core.auth import get_api_key
from ..core.models import GenericErrorMessage, StatusMessage
from ..db.session import get_db
from .crud import ClientConfigurationCRUD
from .models import (
    ClientConfiguration,
    ClientConfigurationPatch,
    ClientConfigurationRead,
)

router = APIRouter()


@router.post(
    "/",
    response_description="Add new client configuration",
    status_code=http_status.HTTP_201_CREATED,
    response_model=ClientConfiguration,
    responses={http_status.HTTP_409_CONFLICT: {"model": GenericErrorMessage}},
    response_model_exclude_unset=True,
    dependencies=[Depends(get_api_key)],
)
async def create_client_config(
    client_config: ClientConfiguration, db: Database = Depends(get_db)
):
    return await ClientConfigurationCRUD(db).create(client_config)


@router.get(
    "/",
    status_code=http_status.HTTP_200_OK,
    response_model=list[ClientConfigurationRead],
    response_model_exclude_unset=True,
    dependencies=[Depends(get_api_key)],
)
async def get_all_client_configs(db: Database = Depends(get_db)):
    return await ClientConfigurationCRUD(db).get_all()


@router.get(
    "/{client_id}",
    status_code=http_status.HTTP_200_OK,
    response_model=ClientConfigurationRead,
    responses={http_status.HTTP_404_NOT_FOUND: {"model": GenericErrorMessage}},
    response_model_exclude_unset=True,
    dependencies=[Depends(get_api_key)],
)
async def get_client_config(client_id: str, db: Database = Depends(get_db)):
    return await ClientConfigurationCRUD(db).get(client_id)


@router.patch(
    "/{client_id}",
    status_code=http_status.HTTP_200_OK,
    response_model=ClientConfigurationRead,
    responses={http_status.HTTP_404_NOT_FOUND: {"model": GenericErrorMessage}},
    response_model_exclude_unset=True,
    dependencies=[Depends(get_api_key)],
)
async def patch_client_config(
    client_id: str,
    data: ClientConfigurationPatch,
    db: Database = Depends(get_db),
):
    return await ClientConfigurationCRUD(db).patch(client_id=client_id, data=data)


@router.delete(
    "/{client_id}",
    status_code=http_status.HTTP_200_OK,
    response_model=StatusMessage,
    responses={http_status.HTTP_404_NOT_FOUND: {"model": GenericErrorMessage}},
    dependencies=[Depends(get_api_key)],
)
async def delete_client_config(client_id: str, db: Database = Depends(get_db)):
    status = await ClientConfigurationCRUD(db).delete(client_id)
    return StatusMessage(status=status, message="The client configuration was deleted")
