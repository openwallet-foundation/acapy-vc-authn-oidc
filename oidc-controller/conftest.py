from api.core.config import settings

import pytest
import mongomock
import logging
import os
import tempfile

# disable mongodb logging when running tests
logging.getLogger("pymongo").setLevel(logging.CRITICAL)


@pytest.fixture()
def db_client():
    def get_mock_db_client() -> mongomock.MongoClient:
        return mongomock.MongoClient()

    return get_mock_db_client


@pytest.fixture()
def db(db_client):
    return db_client().db


# Create a temporary directory for assets to satisfy StaticFiles check in main.py
temp_template_dir = tempfile.mkdtemp()
os.makedirs(os.path.join(temp_template_dir, "assets"), exist_ok=True)

settings.CONTROLLER_TEMPLATE_DIR = temp_template_dir
settings.CONTROLLER_URL = "https://controller"
settings.TESTING = True
settings.ACAPY_PROOF_FORMAT = "indy"
