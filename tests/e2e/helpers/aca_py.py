"""ACA-Py admin API client for E2E tests."""

import asyncio
import httpx


class AcaPyAdminClient:
    """Thin async wrapper around the ACA-Py admin REST API."""

    def __init__(self, admin_url: str, timeout: float = 30.0):
        self._url = admin_url.rstrip("/")
        self._timeout = timeout

    async def wait_for_ready(self, timeout: float = 120.0) -> None:
        """Poll /status until the agent is ready or timeout expires."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            deadline = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < deadline:
                try:
                    r = await client.get(f"{self._url}/status")
                    if r.status_code == 200:
                        return
                except httpx.RequestError:
                    pass
                await asyncio.sleep(2)
        raise TimeoutError(f"ACA-Py agent at {self._url} not ready after {timeout}s")

    async def get_connections(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.get(f"{self._url}/connections")
            r.raise_for_status()
            return r.json().get("results", [])

    async def receive_invitation(self, invitation: dict) -> dict:
        """POST an OOB invitation JSON to the agent and return the connection record."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(
                f"{self._url}/out-of-band/receive-invitation",
                json=invitation,
                params={"auto_accept": "true"},
            )
            r.raise_for_status()
            return r.json()

    async def get_credentials(self) -> list[dict]:
        """Return all credentials stored in the holder wallet."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.get(f"{self._url}/credentials")
            r.raise_for_status()
            return r.json().get("results", [])

    async def wait_for_credential(self, timeout: float = 90.0) -> dict:
        """Wait until at least one credential appears in the wallet."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            creds = await self.get_credentials()
            if creds:
                return creds[0]
            await asyncio.sleep(2)
        raise TimeoutError("Holder wallet has no credentials after bootstrap")
