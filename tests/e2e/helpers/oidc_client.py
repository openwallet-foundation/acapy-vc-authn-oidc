"""OIDC flow client for E2E tests.

Drives the full authorization code flow:
  1. GET /authorize  — returns HTML; parse pid and url_to_message
  2. GET /url/pres_exch/{pres_exch_id}  — returns OOB invitation JSON
  3. GET /callback?pid=…  — returns redirect with auth code
  4. POST /token  — exchange auth code for tokens
"""

import base64
import re
from urllib.parse import parse_qs, urlparse

import httpx


class OIDCFlowClient:
    def __init__(
        self,
        controller_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        timeout: float = 30.0,
    ):
        self._url = controller_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Authorize
    # ------------------------------------------------------------------

    async def authorize(
        self,
        pres_req_conf_id: str,
        state: str = "e2e-test-state",
        nonce: str = "e2e-test-nonce",
    ) -> tuple[str, dict]:
        """GET /authorize and return (pid, invitation_dict).

        The invitation dict is the OOB JSON from /url/pres_exch/{id} — pass
        it directly to the holder agent's receive-invitation endpoint.
        """
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": "openid",
            "pres_req_conf_id": pres_req_conf_id,
            "state": state,
            "nonce": nonce,
        }
        async with httpx.AsyncClient(
            timeout=self._timeout, follow_redirects=False
        ) as c:
            r = await c.get(f"{self._url}/authorize", params=params)
        r.raise_for_status()
        html = r.text

        pid = self._parse_pid(html)
        url_to_message = self._parse_url_to_message(html)
        invitation = await self._fetch_invitation(url_to_message)
        return pid, invitation

    def _parse_pid(self, html: str) -> str:
        """Extract pid (MongoDB ObjectId) from the SSE URL in the rendered HTML.

        Coupled to html-templates/ — looks for /sse/status/{24-char ObjectId}.
        """
        m = re.search(r"/sse/status/([a-f0-9]{24})", html)
        if not m:
            # Fallback: callback URL contains ?pid=...
            m = re.search(r"[?&]pid=([a-f0-9]{24})", html)
        if not m:
            raise ValueError(
                f"Could not find pid in authorize HTML (first 2000 chars): {html[:2000]!r}"
            )
        return m.group(1)

    def _parse_url_to_message(self, html: str) -> str:
        """Extract the QR-code URL from the rendered HTML.

        Coupled to html-templates/ — looks for input value="/url/pres_exch/...".
        The real template renders it as: value="{{ url_to_message }}"
        """
        m = re.search(r'value="([^"]+/url/pres_exch/[^"]+)"', html)
        if not m:
            # Try to find any /url/pres_exch/... pattern
            m = re.search(r"(https?://[^\s\"']+/url/pres_exch/[^\s\"'<>]+)", html)
        if not m:
            raise ValueError(
                f"Could not find url_to_message in authorize HTML (first 2000 chars): {html[:2000]!r}"
            )
        return m.group(1)

    async def _fetch_invitation(self, url_to_message: str) -> dict:
        """GET the url_to_message URL (JSON accept) to retrieve the OOB invitation."""
        # Rewrite host/port to controller_url in case template used an internal URL
        parsed = urlparse(url_to_message)
        local_url = f"{self._url}{parsed.path}"
        if parsed.query:
            local_url += f"?{parsed.query}"

        async with httpx.AsyncClient(timeout=self._timeout) as c:
            r = await c.get(local_url, headers={"Accept": "application/json"})
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Callback + token
    # ------------------------------------------------------------------

    async def get_auth_code(self, pid: str) -> str:
        """GET /callback?pid=… and parse the authorization code from the redirect."""
        async with httpx.AsyncClient(
            timeout=self._timeout, follow_redirects=False
        ) as c:
            r = await c.get(f"{self._url}/callback", params={"pid": pid})

        if r.status_code not in (301, 302, 303, 307, 308):
            raise AssertionError(
                f"Expected redirect from /callback, got {r.status_code}: {r.text[:200]}"
            )

        location = r.headers.get("location", "")
        qs = parse_qs(urlparse(location).query)
        codes = qs.get("code", [])
        if not codes:
            raise ValueError(f"No 'code' in callback redirect: {location!r}")
        return codes[0]

    async def get_token(self, auth_code: str) -> dict:
        """POST /token with the authorization code and return the full token response."""
        credentials = base64.b64encode(
            f"{self._client_id}:{self._client_secret}".encode()
        ).decode()
        data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": self._redirect_uri,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as c:
            r = await c.post(
                f"{self._url}/token",
                data=data,
                headers={"Authorization": f"Basic {credentials}"},
            )
        r.raise_for_status()
        return r.json()
