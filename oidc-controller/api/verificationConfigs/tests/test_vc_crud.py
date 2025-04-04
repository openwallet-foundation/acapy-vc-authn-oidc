import pytest

from api.verificationConfigs.crud import VerificationConfigCRUD
from api.verificationConfigs.models import (
    AttributeFilter,
    ReqPred,
    VerificationConfig,
    VerificationProofRequest,
    VerificationConfigPatch,
    ReqAttr,
)
from api.db.session import COLLECTION_NAMES

from mongomock import MongoClient
from typing import Callable


test_ver_config = VerificationConfig(
    ver_config_id="test_ver_config",
    subject_identifier="test_sub_id",
    proof_request=VerificationProofRequest(
        version="0.0.1", requested_attributes=[], requested_predicates=[]
    ),
)


def test_answer():
    assert True


@pytest.mark.asyncio
async def test_ver_config_get(db_client: Callable[[], MongoClient]):
    client = db_client()
    crud = VerificationConfigCRUD(client.db)

    client.db.get_collection(COLLECTION_NAMES.VER_CONFIGS).insert_one(
        test_ver_config.model_dump()
    )

    result = await crud.get("test_ver_config")
    assert result


@pytest.mark.asyncio
async def test_ver_config_create(db_client: Callable[[], MongoClient]):
    client = db_client()
    crud = VerificationConfigCRUD(client.db)

    await crud.create(test_ver_config)
    document = client.db.get_collection(COLLECTION_NAMES.VER_CONFIGS).find_one(
        {"ver_config_id": "test_ver_config"}
    )
    assert document


@pytest.mark.asyncio
async def test_ver_config_delete(db_client: Callable[[], MongoClient]):
    client = db_client()
    crud = VerificationConfigCRUD(client.db)

    client.db.get_collection(COLLECTION_NAMES.VER_CONFIGS).insert_one(
        test_ver_config.model_dump()
    )

    result = await crud.delete("test_ver_config")
    assert result

    document = client.db.get_collection(COLLECTION_NAMES.VER_CONFIGS).find_one(
        {"ver_config_id": "test_ver_config"}
    )
    assert not document


@pytest.mark.asyncio
async def test_ver_config_patch(db_client: Callable[[], MongoClient]):
    client = db_client()
    crud = VerificationConfigCRUD(client.db)

    client.db.get_collection(COLLECTION_NAMES.VER_CONFIGS).insert_one(
        test_ver_config.model_dump()
    )

    result = await crud.patch(
        "test_ver_config", VerificationConfigPatch(subject_identifier="patched_sub_id")
    )
    assert result

    document = client.db.get_collection(COLLECTION_NAMES.VER_CONFIGS).find_one(
        {"ver_config_id": "test_ver_config"}
    )
    assert document["subject_identifier"] == "patched_sub_id"


@pytest.mark.asyncio
async def test_ver_config_patch_proof_request(db_client: Callable[[], MongoClient]):
    client = db_client()
    crud = VerificationConfigCRUD(client.db)
    client.db.get_collection(COLLECTION_NAMES.VER_CONFIGS).insert_one(
        test_ver_config.model_dump()
    )

    result = await crud.patch(
        "test_ver_config",
        VerificationConfigPatch(
            proof_request=VerificationProofRequest(
                version="0.0.2",
                requested_attributes=[ReqAttr(names=["first_name"], restrictions=[])],
                requested_predicates=[],
            ),
        ),
    )
    assert result

    document = client.db.get_collection(COLLECTION_NAMES.VER_CONFIGS).find_one(
        {"ver_config_id": "test_ver_config"}
    )
    assert document["proof_request"]["version"] == "0.0.2"
    assert len(document["proof_request"]["requested_attributes"][0]["names"]) == 1
    assert (
        document["proof_request"]["requested_attributes"][0]["names"][0] == "first_name"
    )


@pytest.mark.asyncio
async def test_generate_proof_request():
    # Create a sample VerificationConfig object
    verification_config = VerificationConfig(
        ver_config_id="test_ver_config",
        subject_identifier="test_sub_id",
        proof_request=VerificationProofRequest(
            name="test_proof_request",
            version="0.0.1",
            requested_attributes=[
                ReqAttr(
                    names=["first_name", "last_name"],
                    label="name_label",
                    restrictions=[
                        AttributeFilter(schema_id="schema_1"),
                        AttributeFilter(cred_def_id="cred_def_1"),
                    ],
                )
            ],
            requested_predicates=[
                ReqPred(
                    name="age",
                    label="age_label",
                    restrictions=[
                        AttributeFilter(schema_id="schema_2"),
                        AttributeFilter(issuer_did="issuer_1"),
                    ],
                    p_value=18,
                    p_type=">=",
                )
            ],
        ),
    )

    # Generate the proof request
    proof_request = verification_config.generate_proof_request()

    # Assertions to verify the generated proof request
    assert proof_request["name"] == "test_proof_request"
    assert proof_request["version"] == "0.0.1"

    # Check requested attributes
    assert "name_label" in proof_request["requested_attributes"]
    attr = proof_request["requested_attributes"]["name_label"]
    assert attr["names"] == ["first_name", "last_name"]
    assert len(attr["restrictions"]) == 2
    assert attr["restrictions"][0]["schema_id"] == "schema_1"
    assert attr["restrictions"][1]["cred_def_id"] == "cred_def_1"

    # Check requested predicates
    assert "age_label" in proof_request["requested_predicates"]
    pred = proof_request["requested_predicates"]["age_label"]
    assert pred["name"] == "age"
    assert pred["p_value"] == 18
    assert pred["p_type"] == ">="
    assert len(pred["restrictions"]) == 2
    assert pred["restrictions"][0]["schema_id"] == "schema_2"
    assert pred["restrictions"][1]["issuer_did"] == "issuer_1"
