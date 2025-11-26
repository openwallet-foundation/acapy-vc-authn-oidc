from datetime import UTC, datetime
from typing import TypedDict

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, field_serializer
from pydantic_core import core_schema
from pyop.userinfo import Userinfo


class PyObjectId(ObjectId):
    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type, handler
    ) -> core_schema.CoreSchema:
        return core_schema.with_info_plain_validator_function(cls.validate)

    @classmethod
    def validate(cls, v, info):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")


class HealthCheck(BaseModel):
    name: str
    version: str
    description: str


class StatusMessage(BaseModel):
    status: bool
    message: str


class UUIDModel(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")

    model_config = ConfigDict()

    @field_serializer("id")
    def serialize_id(self, value: PyObjectId) -> str:
        return str(value)


class TimestampModel(BaseModel):
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GenericErrorMessage(BaseModel):
    detail: str


# Currently used as a TypedDict since it can be used as a part of a
# Pydantic class but a Pydantic class can not inherit from TypedDict
# and and BaseModel
class RevealedAttribute(TypedDict, total=False):
    sub_proof_index: int
    values: dict


class VCUserinfo(Userinfo):
    """
    User database for VC-based Identity provider: since no users are
    known ahead of time, a new user is created with
    every authentication request.
    
    This implementation stores custom claims (from VC presentations)
    in memory so they can be included in ID tokens by PyOP.
    """

    def __init__(self, db):
        super().__init__(db)
        self._claims_cache = {}
    
    def set_claims_for_user(self, user_id, claims):
        """
        Store claims for a specific user_id so they can be retrieved
        later when PyOP generates the ID token.
        
        Args:
            user_id: The user identifier (should match what PyOP uses)
            claims: Dictionary of claims to store (pres_req_conf_id,
                    vc_presented_attributes, etc.)
        """
        try:
            if user_id is None:
                raise ValueError(
                    "user_id cannot be None when storing claims"
                )
            self._claims_cache[user_id] = claims
            print(
                f"VCUserinfo: Stored claims for user_id: {user_id}, "
                f"claims keys: {list(claims.keys())}"
            )
        except Exception as e:
            print(f"VCUserinfo.set_claims_for_user ERROR: {e}")
            raise

    def __getitem__(self, item):
        """
        Return stored claims for the given user_id.
        PyOP may call this method to retrieve user info.
        """
        try:
            if item is None:
                raise ValueError(
                    "user_id (item) cannot be None when retrieving claims"
                )
            claims = self._claims_cache.get(item, {})
            print(
                f"VCUserinfo.__getitem__ called for item: {item}, "
                f"returning claims keys: {list(claims.keys())}"
            )
            return claims
        except Exception as e:
            print(f"VCUserinfo.__getitem__ ERROR: {e}")
            raise

    def get_claims_for(self, user_id, requested_claims, userinfo=None):
        """
        Return stored claims for the given user_id.
        PyOP calls this method when generating ID tokens.
        
        Args:
            user_id: The user identifier to look up
            requested_claims: Claims requested by the client (ignored)
            userinfo: Additional userinfo (ignored)
        
        Returns:
            Dictionary of claims for this user, including custom claims
            from VC presentation
        """
        try:
            if user_id is None:
                raise ValueError(
                    "user_id cannot be None when retrieving claims"
                )
            
            claims = self._claims_cache.get(user_id, {})
            print(f"VCUserinfo.get_claims_for called for user_id: {user_id}")
            print(f"  Cached user_ids: {list(self._claims_cache.keys())}")
            print(f"  Returning claims keys: {list(claims.keys())}")
            
            return claims
        except Exception as e:
            print(f"VCUserinfo.get_claims_for ERROR: {e}")
            raise

