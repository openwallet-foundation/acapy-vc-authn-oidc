import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from api.main import app, logging_middleware
from fastapi import Request

client = TestClient(app)

def test_read_root():
    """
    Test the root endpoint.
    Covers: main.py route definitions.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "health": "ok"}

@pytest.mark.asyncio
async def test_logging_middleware_exception_handling():
    """
    Directly test the middleware exception handling logic.
    Covers: main.py middleware exception block (lines 189-205).
    """
    # Mock request object
    mock_request = MagicMock(spec=Request)
    mock_request.url = "http://testserver/error"
    mock_request.cookies = {}
    mock_request.scope = {"type": "http"}
    
    # Mock call_next to simulate an application crash
    async def mock_call_next(request):
        raise RuntimeError("Simulated Crash")
        
    # Call the middleware directly
    response = await logging_middleware(mock_request, mock_call_next)
    
    # Verify it catches the error and returns 500 JSON
    assert response.status_code == 500
    
    import json
    body = json.loads(response.body)
    assert body["status"] == "error"
    assert body["message"] == "Internal Server Error"