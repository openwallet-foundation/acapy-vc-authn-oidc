from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx
import structlog

from api.adapters.acapy.config import (
    AgentConfig,
    MultiTenantAcapy,
    SingleTenantAcapy,
    TractionTenantAcapy,
)
from api.config import settings
from api.core.acapy.models import (
    CreatePresentationResponse,
    OobCreateInvitationResponse,
)
from api.core.models import FrozenModel

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

CREATE_PRESENTATION_REQUEST_URL = "/present-proof-2.0/create-request"
PRESENT_PROOF_RECORDS = "/present-proof-2.0/records"
SEND_PRESENTATION_REQUEST_URL = "/present-proof-2.0/send-request"
PRESENT_PROOF_PROBLEM_REPORT_URL = (
    "/present-proof-2.0/records/{pres_ex_id}/problem-report"
)
OOB_CREATE_INVITATION = "/out-of-band/create-invitation"
OOB_RECORDS_URI = "/out-of-band/records"
OOB_INVITATIONS_URI = "/out-of-band/invitations"
CONNECTIONS_URI = "/connections"


@dataclass(frozen=True)
class AcapyError:
    """An expected failure talking to ACA-Py, returned instead of raised.

    Every AcapyClient method follows one contract:

    - Queries return ``T | AcapyError`` and commands return
      ``None | AcapyError``, where None means it worked.
    - AcapyError means ACA-Py could not be reached (``httpx.HTTPError``),
      answered with an unexpected status, or sent a reply that does not
      parse. The client does not log it; the caller decides what it means
      and logs it.
    - Anything else is a bug and raises.

    ``reason`` is for our logs only. It can include ACA-Py's response body,
    so never forward it to the wallet.
    """

    reason: str


def _parse[M: FrozenModel](model: type[M], resp: httpx.Response) -> M | AcapyError:
    try:
        return model.model_validate(resp.json())
    except ValueError as e:  # bad JSON or a ValidationError
        return AcapyError(f"unexpected reply from ACA-Py: {e}")


def _done(resp: httpx.Response | AcapyError) -> AcapyError | None:
    """The result of a command, which only cares whether the call worked."""
    return resp if isinstance(resp, AcapyError) else None


class AcapyClient:
    acapy_host = settings.ACAPY_ADMIN_URL
    service_endpoint = settings.ACAPY_AGENT_URL

    agent_config: AgentConfig

    def __init__(self, http_client: httpx.AsyncClient):
        self._http_client = http_client

        if settings.ACAPY_TENANCY == "multi":
            self.agent_config = MultiTenantAcapy(http_client)
        elif settings.ACAPY_TENANCY == "traction":
            self.agent_config = TractionTenantAcapy(http_client)
        elif settings.ACAPY_TENANCY == "single":
            self.agent_config = SingleTenantAcapy(http_client)
        else:
            logger.warning("ACAPY_TENANCY not set, assuming SingleTenantAcapy")
            self.agent_config = SingleTenantAcapy(http_client)

    async def _call(
        self,
        method: str,
        path: str,
        ok: tuple[int, ...] = (200,),
        **kwargs: Any,
    ) -> httpx.Response | AcapyError:
        """Send one request to the admin API, applying the AcapyError contract
        to transport errors and unexpected statuses."""
        try:
            resp = await self._http_client.request(
                method,
                self.acapy_host + path,
                headers=await self.agent_config.get_headers(),
                **kwargs,
            )
        except httpx.HTTPError as e:
            return AcapyError(f"could not reach ACA-Py: {e}")
        if resp.status_code not in ok:
            return AcapyError(
                f"{method} {path} returned {resp.status_code}: {resp.text}"
            )
        return resp

    async def create_presentation_request(
        self, presentation_request_configuration: dict
    ) -> CreatePresentationResponse | AcapyError:
        format_key = settings.ACAPY_PROOF_FORMAT
        present_proof_payload = {
            "presentation_request": {format_key: presentation_request_configuration},
            "auto_remove": True,
            "auto_remove_on_failure": True,
        }
        resp = await self._call(
            "POST", CREATE_PRESENTATION_REQUEST_URL, json=present_proof_payload
        )
        if isinstance(resp, AcapyError):
            return resp
        return _parse(CreatePresentationResponse, resp)

    async def delete_presentation_record(
        self, presentation_exchange_id: UUID | str
    ) -> AcapyError | None:
        """Delete a presentation record. A record that is already gone (e.g.
        ACA-Py auto-removal) counts as deleted."""
        return _done(
            await self._call(
                "DELETE",
                f"{PRESENT_PROOF_RECORDS}/{presentation_exchange_id}",
                ok=(200, 404),
            )
        )

    async def _get_records_page(
        self, uri: str, limit: int, offset: int, filters: dict | None = None
    ) -> list[dict] | AcapyError:
        """Fetch one page of records from a paginated ACA-Py list endpoint.

        A failure is an AcapyError, never an empty page, so callers can stop
        instead of mistaking it for the end of the records.
        """
        params = {"limit": limit, "offset": offset, **(filters or {})}
        resp = await self._call("GET", uri, params=params)
        if isinstance(resp, AcapyError):
            return resp
        try:
            return resp.json().get("results", [])
        except ValueError as e:
            return AcapyError(f"unexpected reply from ACA-Py: {e}")

    async def get_presentation_records_page(
        self, limit: int, offset: int = 0, role: str | None = "verifier"
    ) -> list[dict] | AcapyError:
        """Get a page of presentation exchange records (verifier role by default)."""
        filters = {"role": role} if role else None
        return await self._get_records_page(
            PRESENT_PROOF_RECORDS, limit, offset, filters
        )

    async def get_connections_page(
        self, limit: int, offset: int = 0
    ) -> list[dict] | AcapyError:
        """Get a page of connection records in any state."""
        return await self._get_records_page(CONNECTIONS_URI, limit, offset)

    async def get_oob_records_page(
        self, limit: int, offset: int = 0, role: str | None = "sender"
    ) -> list[dict] | AcapyError:
        """Get a page of out-of-band records (sender role by default)."""
        filters = {"role": role} if role else None
        return await self._get_records_page(OOB_RECORDS_URI, limit, offset, filters)

    async def delete_oob_invitation(self, invi_msg_id: str) -> AcapyError | None:
        """Delete the OOB record and any connection created from an invitation.
        One that is already gone counts as deleted."""
        return _done(
            await self._call(
                "DELETE", f"{OOB_INVITATIONS_URI}/{invi_msg_id}", ok=(200, 404)
            )
        )

    async def oob_create_invitation(
        self, presentation_exchange: dict, use_public_did: bool
    ) -> OobCreateInvitationResponse | AcapyError:
        create_invitation_payload = {
            "attachments": [
                {
                    "id": presentation_exchange["pres_ex_id"],
                    "type": "present-proof",
                    "data": {"json": presentation_exchange},
                }
            ],
            "use_public_did": use_public_did,
            "my_label": settings.INVITATION_LABEL,
        }
        resp = await self._call(
            "POST", OOB_CREATE_INVITATION, json=create_invitation_payload
        )
        if isinstance(resp, AcapyError):
            return resp
        return _parse(OobCreateInvitationResponse, resp)

    async def send_presentation_request_by_connection(
        self, connection_id: str, presentation_request_configuration: dict
    ) -> CreatePresentationResponse | AcapyError:
        """Send a presentation request to an established connection."""
        format_key = settings.ACAPY_PROOF_FORMAT
        present_proof_payload = {
            "connection_id": connection_id,
            "presentation_request": {format_key: presentation_request_configuration},
            "auto_remove": True,
            # Ignored by ACA-Py 1.7 send-request; failures rely on --no-preserve-failed-exchange-records
            "auto_remove_on_failure": True,
        }
        resp = await self._call(
            "POST", SEND_PRESENTATION_REQUEST_URL, json=present_proof_payload
        )
        if isinstance(resp, AcapyError):
            return resp
        return _parse(CreatePresentationResponse, resp)

    async def delete_connection(self, connection_id: str) -> AcapyError | None:
        """Delete a connection. One that is already gone (e.g. removed with its
        OOB invitation) counts as deleted."""
        return _done(
            await self._call(
                "DELETE", f"{CONNECTIONS_URI}/{connection_id}", ok=(200, 404)
            )
        )

    async def send_problem_report(
        self, pres_ex_id: str, description: str
    ) -> AcapyError | None:
        """Tell the wallet a presentation exchange failed. DESCRIPTION is sent
        to the holder, so keep internal details out of it."""
        return _done(
            await self._call(
                "POST",
                PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
                json={"description": description},
            )
        )

    async def create_connection_invitation(
        self,
        multi_use: bool = False,
        presentation_exchange: dict | None = None,
        use_public_did: bool = False,
        alias: str | None = None,
        auto_accept: bool | None = None,
        metadata: dict | None = None,
    ) -> OobCreateInvitationResponse | AcapyError:
        """
        Create an out-of-band invitation for either ephemeral or persistent connections.

        Args:
            multi_use: Whether this is a non-ephemeral (multi-use) connection (default: False)
            presentation_exchange: Optional presentation exchange to attach to invitation
            use_public_did: Whether to use public DID for the invitation (default: False)
            alias: Optional alias for the connection (default: None)
            auto_accept: Whether to auto-accept the connection (default: None - use configuration)
            metadata: Optional metadata to attach to the connection (default: None)

        Returns:
            The invitation details, or AcapyError
        """
        if multi_use:
            goal_code = "aries.vc.verify"
            goal = "Verify credentials for authentication"
        else:
            goal_code = "aries.vc.verify.once"
            goal = "Verify credentials for single-use authentication"

        create_invitation_payload = {
            "use_public_did": use_public_did,
            "my_label": settings.INVITATION_LABEL,
            "goal_code": goal_code,
            "goal": goal,
        }

        if not presentation_exchange:
            create_invitation_payload["handshake_protocols"] = [
                "https://didcomm.org/didexchange/1.0",
                "https://didcomm.org/connections/1.0",
            ]

        if presentation_exchange:
            create_invitation_payload["attachments"] = [
                {
                    "id": presentation_exchange["pres_ex_id"],
                    "type": "present-proof",
                    "data": {"json": presentation_exchange},
                }
            ]

        if alias is not None:
            create_invitation_payload["alias"] = alias
        if metadata:
            create_invitation_payload["metadata"] = metadata

        params = {"multi_use": str(multi_use).lower()}
        if auto_accept is not None:
            params["auto_accept"] = str(auto_accept).lower()

        resp = await self._call(
            "POST",
            OOB_CREATE_INVITATION,
            json=create_invitation_payload,
            params=params,
        )
        if isinstance(resp, AcapyError):
            return resp
        return _parse(OobCreateInvitationResponse, resp)
