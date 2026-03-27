"""SSE client for E2E tests.

Consumes the /sse/status/{pid} endpoint and waits for a specific status.
Uses httpx streaming so no extra SSE library is needed.

Wire format (from api/routers/sse.py _format_event):
    event: status\\ndata: {"status": "verified"}\\n\\n
"""

import asyncio
import json

import httpx


class SSEClient:
    """Subscribe to /sse/status/{pid} and wait for a terminal status."""

    def __init__(self, controller_url: str, timeout: float = 60.0):
        self._url = controller_url.rstrip("/")
        self._timeout = timeout

    async def wait_for_status(
        self,
        pid: str,
        expected: str,
        timeout: float | None = None,
    ) -> str:
        """Stream SSE events for *pid* and return when *expected* status arrives.

        Also returns immediately on any terminal status (verified, failed,
        abandoned, expired) so tests don't hang forever.

        Raises TimeoutError if *timeout* seconds elapse without a terminal event.
        """
        deadline = timeout or self._timeout
        try:
            return await asyncio.wait_for(
                self._stream_until(pid, expected), timeout=deadline
            )
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"SSE timed out after {deadline}s waiting for '{expected}' (pid={pid})"
            )

    async def _stream_until(self, pid: str, expected: str) -> str:
        TERMINAL = {"verified", "failed", "abandoned", "expired"}
        url = f"{self._url}/sse/status/{pid}"

        async with httpx.AsyncClient(timeout=httpx.Timeout(None)) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                event_type: str | None = None
                async for line in response.aiter_lines():
                    line = line.strip()
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:") and event_type == "status":
                        data = json.loads(line[5:].strip())
                        status = data.get("status", "")
                        if status == expected or status in TERMINAL:
                            return status
                        event_type = None
                    elif line == "":
                        event_type = None

        raise TimeoutError(f"SSE stream ended without '{expected}' for pid={pid}")

    async def get_current_status(self, pid: str) -> str:
        """Return the first status event emitted for *pid* (used for expiry checks)."""
        return await self.wait_for_status(pid, expected="__any__", timeout=10.0)
