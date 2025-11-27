from api.core.config import settings

import pytest
import mongomock
import logging
import os
import tempfile
import shutil


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


# Needed because api.main executes StaticFiles() check at import time.
try:
    # Ensure we don't overwrite if it exists
    if not os.path.exists(settings.CONTROLLER_TEMPLATE_DIR):
        # Use a temp dir for tests if the real one is missing
        temp_template_dir = tempfile.mkdtemp()
        settings.CONTROLLER_TEMPLATE_DIR = temp_template_dir

    # Ensure assets subdir exists
    assets_dir = os.path.join(settings.CONTROLLER_TEMPLATE_DIR, "assets")
    os.makedirs(assets_dir, exist_ok=True)
except Exception as e:
    print(f"Warning: Failed to setup test assets directory: {e}")


settings.CONTROLLER_URL = "https://controller"
settings.TESTING = True
settings.ACAPY_PROOF_FORMAT = "indy"
