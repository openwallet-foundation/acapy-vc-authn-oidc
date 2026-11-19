from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .examples import ex_ver_config
from .helpers import replace_proof_variables


# Slightly modified from ACAPY models.
class AttributeFilter(BaseModel, frozen=True):
    schema_id: str | None = None
    cred_def_id: str | None = None
    schema_name: str | None = None
    schema_issuer_did: str | None = None
    schema_version: str | None = None
    issuer_did: str | None = None


class ReqAttr(BaseModel, frozen=True):
    names: list[str]
    label: str | None = None
    restrictions: list[AttributeFilter]


class ReqPred(BaseModel, frozen=True):
    name: str
    label: str | None = None
    restrictions: list[AttributeFilter]
    p_value: int | str
    p_type: str


class VerificationProofRequest(BaseModel, frozen=True):
    name: str | None = None
    version: str = Field(pattern="[0-9](.[0.9])*", examples=["0.0.1"])
    non_revoked: str | None = None
    requested_attributes: list[ReqAttr]
    requested_predicates: list[ReqPred]


class MetaData(BaseModel, frozen=True):
    title: str | None = Field(default=None)
    claims: list[str] | None = Field(default=None)


class VerificationConfigBase(BaseModel, frozen=True):
    subject_identifier: str = Field()
    proof_request: VerificationProofRequest = Field()
    generate_consistent_identifier: bool | None = Field(default=False)
    include_v1_attributes: bool | None = Field(default=False)
    metadata: dict[str, MetaData] | None = Field(default=None)

    def generate_proof_request(self, now: datetime, set_non_revoked: bool):
        result = {
            "name": "proof_requested",
            "version": "0.0.1",
            "requested_attributes": {},
            "requested_predicates": {},
        }
        if self.proof_request.name:
            result["name"] = self.proof_request.name
        for i, req_attr in enumerate(self.proof_request.requested_attributes):
            label = req_attr.label or "req_attr_" + str(i)
            result["requested_attributes"][label] = req_attr.model_dump(
                exclude_none=True
            )
            if set_non_revoked:
                result["requested_attributes"][label]["non_revoked"] = {
                    "from": int(now.timestamp()),
                    "to": int(now.timestamp()),
                }
        for i, req_pred in enumerate(self.proof_request.requested_predicates):
            label = req_pred.label or "req_pred_" + str(i)
            result["requested_predicates"][label] = req_pred.model_dump(
                exclude_none=True
            )
            if set_non_revoked:
                result["requested_predicates"][label]["non_revoked"] = {
                    "from": int(now.timestamp()),
                    "to": int(now.timestamp()),
                }
        # Recursively check for subistitution variables and invoke replacement function
        result = replace_proof_variables(result, now)
        return result

    model_config = ConfigDict(json_schema_extra={"example": ex_ver_config})


class VerificationConfig(VerificationConfigBase, frozen=True):
    ver_config_id: str = Field()


class VerificationConfigRead(VerificationConfigBase, frozen=True):
    ver_config_id: str = Field()


class VerificationConfigPatch(BaseModel, frozen=True):
    subject_identifier: str | None = Field(None)
    proof_request: VerificationProofRequest | None = Field(None)
    generate_consistent_identifier: bool | None = Field(default=False)
    include_v1_attributes: bool | None = Field(default=False)
    metadata: dict[str, MetaData] | None = Field(default=None)

    model_config = VerificationConfigBase.model_config
