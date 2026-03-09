"""Tests for verification config router endpoints."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import mongomock

from api.verificationConfigs.router import router
from api.verificationConfigs.models import VerificationConfig, VerificationProofRequest
from api.db.session import get_db
from api.core.auth import get_api_key


TEST_VER_CONFIG = VerificationConfig(
    ver_config_id="test-config",
    subject_identifier="test_sub",
    proof_request=VerificationProofRequest(
        version="0.0.1", requested_attributes=[], requested_predicates=[]
    ),
)


@pytest.fixture
def mock_db():
    client = mongomock.MongoClient()
    return client.db


@pytest.fixture
def app(mock_db):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_api_key] = lambda: "test-key"
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_create_ver_config(client, mock_db):
    response = client.post("/", json=TEST_VER_CONFIG.model_dump())
    assert response.status_code == 201
    assert response.json()["ver_config_id"] == "test-config"


VER_CONFIG_COLLECTION = "verification_configuration"


def test_get_all_ver_configs(client, mock_db):
    mock_db.get_collection(VER_CONFIG_COLLECTION).insert_one(
        TEST_VER_CONFIG.model_dump()
    )
    response = client.get("/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) == 1


def test_get_ver_config(client, mock_db):
    mock_db.get_collection(VER_CONFIG_COLLECTION).insert_one(
        TEST_VER_CONFIG.model_dump()
    )
    response = client.get("/test-config")
    assert response.status_code == 200
    assert response.json()["ver_config_id"] == "test-config"


def test_patch_ver_config(client, mock_db):
    mock_db.get_collection(VER_CONFIG_COLLECTION).insert_one(
        TEST_VER_CONFIG.model_dump()
    )
    response = client.patch("/test-config", json={"subject_identifier": "new_sub"})
    assert response.status_code == 200
    assert response.json()["subject_identifier"] == "new_sub"


def test_delete_ver_config(client, mock_db):
    mock_db.get_collection(VER_CONFIG_COLLECTION).insert_one(
        TEST_VER_CONFIG.model_dump()
    )
    response = client.delete("/test-config")
    assert response.status_code == 200
    assert response.json()["status"] is True


def test_get_proof_request_explorer(client, mock_db):
    mock_db.get_collection(VER_CONFIG_COLLECTION).insert_one(
        TEST_VER_CONFIG.model_dump()
    )
    dummy_html = "<html>{{ ver_configs }}</html>"
    with patch(
        "builtins.open",
        MagicMock(
            return_value=MagicMock(
                __enter__=MagicMock(
                    return_value=MagicMock(read=MagicMock(return_value=dummy_html))
                ),
                __exit__=MagicMock(return_value=False),
                read=MagicMock(return_value=dummy_html),
            )
        ),
    ):
        response = client.get("/explorer")
    assert response.status_code == 200
