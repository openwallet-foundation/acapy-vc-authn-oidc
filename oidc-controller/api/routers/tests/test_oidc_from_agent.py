"""Tests for how /authorize reports ACA-Py failures."""

import pytest
from fastapi import HTTPException

from api.adapters.acapy.client import AcapyError
from api.routers.oidc import _from_agent


def test_acapy_error_becomes_502_without_the_reason():
    with pytest.raises(HTTPException) as excinfo:
        _from_agent(AcapyError("connection refused to http://aca-py:8031"))

    assert excinfo.value.status_code == 502
    assert "aca-py:8031" not in str(excinfo.value.detail)


def test_success_passes_through():
    value = object()
    assert _from_agent(value) is value
