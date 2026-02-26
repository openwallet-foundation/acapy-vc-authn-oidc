from uuid import UUID

import httpx
import structlog

from ..config import settings
from .config import (
    AgentConfig,
    MultiTenantAcapy,
    SingleTenantAcapy,
    TractionTenantAcapy,
)
from .models import CreatePresentationResponse, OobCreateInvitationResponse, WalletDid

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

WALLET_DID_URI = "/wallet/did"
PUBLIC_WALLET_DID_URI = "/wallet/did/public"
CREATE_PRESENTATION_REQUEST_URL = "/present-proof-2.0/create-request"
PRESENT_PROOF_RECORDS = "/present-proof-2.0/records"
SEND_PRESENTATION_REQUEST_URL = "/present-proof-2.0/send-request"
PRESENT_PROOF_PROBLEM_REPORT_URL = (
    "/present-proof-2.0/records/{pres_ex_id}/problem-report"
)
OOB_CREATE_INVITATION = "/out-of-band/create-invitation"
CONNECTIONS_URI = "/connections"


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

    async def create_presentation_request(
        self, presentation_request_configuration: dict
    ) -> CreatePresentationResponse:
        logger.debug(">>> create_presentation_request")

        format_key = settings.ACAPY_PROOF_FORMAT
        present_proof_payload = {
            "presentation_request": {format_key: presentation_request_configuration}
        }

        resp = await self._http_client.post(
            self.acapy_host + CREATE_PRESENTATION_REQUEST_URL,
            headers=await self.agent_config.get_headers(),
            json=present_proof_payload,
        )

        assert resp.status_code == 200, resp.content

        result = CreatePresentationResponse.model_validate(resp.json())

        logger.debug("<<< create_presenation_request")
        return result

    async def get_presentation_request(self, presentation_exchange_id: UUID | str):
        logger.debug(">>> get_presentation_request")

        resp = await self._http_client.get(
            self.acapy_host
            + PRESENT_PROOF_RECORDS
            + "/"
            + str(presentation_exchange_id),
            headers=await self.agent_config.get_headers(),
        )

        assert resp.status_code == 200, resp.content

        logger.debug(f"<<< get_presentation_request -> {resp.json()}")
        return resp.json()

    async def delete_presentation_record(
        self, presentation_exchange_id: UUID | str
    ) -> bool:
        """Delete a presentation record by ID"""
        logger.debug(f">>> delete_presentation_record: {presentation_exchange_id}")

        try:
            resp = await self._http_client.delete(
                f"{self.acapy_host}{PRESENT_PROOF_RECORDS}/{presentation_exchange_id}",
                headers=await self.agent_config.get_headers(),
            )

            success = resp.status_code == 200
            if success:
                logger.debug("<<< delete_presentation_record -> Success")
            else:
                logger.warning(
                    f"<<< delete_presentation_record -> Failed: {resp.status_code}, {resp.content}"
                )
            return success

        except Exception as e:
            logger.error(
                f"Failed to delete presentation record {presentation_exchange_id}: {e}"
            )
            return False

    async def get_all_presentation_records(self) -> list[dict]:
        """Get all presentation records for cleanup purposes"""
        logger.debug(">>> get_all_presentation_records")

        try:
            resp = await self._http_client.get(
                f"{self.acapy_host}{PRESENT_PROOF_RECORDS}",
                headers=await self.agent_config.get_headers(),
            )

            if resp.status_code != 200:
                logger.warning(
                    f"Failed to get presentation records: {resp.status_code}, {resp.content}"
                )
                return []

            records = resp.json().get("results", [])
            logger.debug(f"<<< get_all_presentation_records -> {len(records)} records")
            return records

        except Exception as e:
            logger.error(f"Failed to get all presentation records: {e}")
            return []

    async def get_wallet_did(self, public=False) -> WalletDid:
        logger.debug(">>> get_wallet_did")
        url = (
            self.acapy_host + PUBLIC_WALLET_DID_URI
            if public
            else self.acapy_host + WALLET_DID_URI
        )

        resp = await self._http_client.get(
            url,
            headers=await self.agent_config.get_headers(),
        )

        assert resp.status_code == 200, f"{resp.status_code}::{resp.content}"

        data = resp.json()
        resp_payload = data["result"] if public else data["results"][0]
        did = WalletDid.model_validate(resp_payload)

        logger.debug(f"<<< get_wallet_did -> {did}")
        return did

    async def oob_create_invitation(
        self, presentation_exchange: dict, use_public_did: bool
    ) -> OobCreateInvitationResponse:
        logger.debug(">>> oob_create_invitation")
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

        resp = await self._http_client.post(
            self.acapy_host + OOB_CREATE_INVITATION,
            headers=await self.agent_config.get_headers(),
            json=create_invitation_payload,
        )

        assert resp.status_code == 200, resp.content

        result = OobCreateInvitationResponse.model_validate(resp.json())

        logger.debug("<<< oob_create_invitation")
        return result

    async def send_presentation_request_by_connection(
        self, connection_id: str, presentation_request_configuration: dict
    ) -> CreatePresentationResponse:
        """
        Send a presentation request to an existing connection.
        """
        logger.debug(">>> send_presentation_request_by_connection")

        format_key = settings.ACAPY_PROOF_FORMAT
        present_proof_payload = {
            "connection_id": connection_id,
            "presentation_request": {format_key: presentation_request_configuration},
        }

        resp = await self._http_client.post(
            self.acapy_host + SEND_PRESENTATION_REQUEST_URL,
            headers=await self.agent_config.get_headers(),
            json=present_proof_payload,
        )

        assert resp.status_code == 200, resp.content

        result = CreatePresentationResponse.model_validate(resp.json())

        logger.debug("<<< send_presentation_request_by_connection")
        return result

    async def get_connection(self, connection_id: str) -> dict:
        """Get details of a specific connection."""
        logger.debug(">>> get_connection")

        resp = await self._http_client.get(
            self.acapy_host + CONNECTIONS_URI + "/" + connection_id,
            headers=await self.agent_config.get_headers(),
        )

        assert resp.status_code == 200, resp.content

        logger.debug(f"<<< get_connection -> {resp.json()}")
        return resp.json()

    async def list_connections(self, state: str | None = None) -> list[dict]:
        """List all connections, optionally filtered by state."""
        logger.debug(">>> list_connections")

        params = {"state": state} if state else {}

        resp = await self._http_client.get(
            self.acapy_host + CONNECTIONS_URI,
            headers=await self.agent_config.get_headers(),
            params=params,
        )

        assert resp.status_code == 200, resp.content

        connections = resp.json().get("results", [])
        logger.debug(f"<<< list_connections -> {len(connections)} connections")
        return connections

    async def _get_connections_page(
        self, state: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[dict]:
        """Get a page of connections with pagination support."""
        logger.debug(
            f">>> _get_connections_page: state={state}, limit={limit}, offset={offset}"
        )

        params = {
            "limit": limit,
            "offset": offset,
            **({"state": state} if state else {}),
        }

        try:
            resp = await self._http_client.get(
                self.acapy_host + CONNECTIONS_URI,
                headers=await self.agent_config.get_headers(),
                params=params,
            )

            if resp.status_code != 200:
                logger.warning(f"Failed to get connections page: {resp.status_code}")
                return []

            connections = resp.json().get("results", [])
            logger.debug(f"<<< _get_connections_page -> {len(connections)} connections")
            return connections

        except Exception as e:
            logger.error(f"Error getting connections page: {e}")
            return []

    async def get_connections_batched(
        self, state: str = "invitation", batch_size: int = 100
    ):
        """
        Get connections in batches using async iterator pattern for memory efficiency.

        Yields:
            list[dict]: Batches of connection records
        """
        logger.debug(
            f">>> get_connections_batched: state={state}, batch_size={batch_size}"
        )

        offset = 0
        total_yielded = 0

        while True:
            batch = await self._get_connections_page(state, batch_size, offset)

            if not batch:
                break

            total_yielded += len(batch)
            logger.debug(
                f"Yielding batch of {len(batch)} connections (total so far: {total_yielded})"
            )
            yield batch

            if len(batch) < batch_size:
                break

            offset += batch_size

        logger.debug(
            f"<<< get_connections_batched -> yielded {total_yielded} total connections"
        )

    async def delete_connection(self, connection_id: str) -> bool:
        """Delete a connection."""
        logger.debug(">>> delete_connection", connection_id=connection_id)

        try:
            resp = await self._http_client.delete(
                self.acapy_host + CONNECTIONS_URI + "/" + connection_id,
                headers=await self.agent_config.get_headers(),
            )

            success = resp.status_code == 200
            if success:
                logger.debug("<<< delete_connection -> Success")
            else:
                logger.warning(
                    f"<<< delete_connection -> Failed: {resp.status_code}, {resp.content}"
                )
            return success

        except Exception as e:
            logger.error(f"Failed to delete connection {connection_id}: {e}")
            return False

    async def delete_presentation_record_and_connection(
        self, presentation_exchange_id: UUID | str, connection_id: str | None = None
    ) -> tuple[bool, bool | None, list[str]]:
        """
        Delete a presentation record and optionally its associated connection.

        Returns:
            tuple[bool, bool | None, list[str]]:
                - presentation_deleted: True if presentation record was successfully deleted
                - connection_deleted: True/False if attempted, None if not attempted
                - errors: List of error messages from failed operations
        """
        logger.debug(
            f">>> delete_presentation_record_and_connection: pres_ex={presentation_exchange_id}, conn={connection_id}"
        )

        presentation_deleted = False
        connection_deleted = None
        errors = []

        if presentation_exchange_id:
            try:
                presentation_deleted = await self.delete_presentation_record(
                    presentation_exchange_id
                )
                if not presentation_deleted:
                    errors.append(
                        f"Failed to delete presentation record {presentation_exchange_id}"
                    )
            except Exception as e:
                error_msg = f"Error deleting presentation record {presentation_exchange_id}: {e}"
                errors.append(error_msg)
                logger.error(error_msg)

        # TODO: make mandatory when we drop OOB
        if connection_id:
            try:
                connection_deleted = await self.delete_connection(connection_id)
                if not connection_deleted:
                    errors.append(f"Failed to delete connection {connection_id}")
            except Exception as e:
                error_msg = f"Error deleting connection {connection_id}: {e}"
                errors.append(error_msg)
                logger.error(error_msg)

        logger.debug(
            f"<<< delete_presentation_record_and_connection -> pres:{presentation_deleted}, conn:{connection_deleted}"
        )
        return presentation_deleted, connection_deleted, errors

    async def send_problem_report(self, pres_ex_id: str, description: str) -> bool:
        """Send a problem report for a presentation exchange."""
        logger.debug(">>> send_problem_report")

        try:
            resp = await self._http_client.post(
                self.acapy_host
                + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
                json={"description": description},
                headers=await self.agent_config.get_headers(),
            )

            success = resp.status_code == 200
            logger.debug(f"<<< send_problem_report -> {success}")

            if not success:
                logger.error(
                    f"Failed to send problem report: {resp.status_code} - {resp.content}"
                )

            return success

        except Exception as e:
            logger.error(f"Error sending problem report: {e}")
            return False

    async def create_connection_invitation(
        self,
        multi_use: bool = False,
        presentation_exchange: dict | None = None,
        use_public_did: bool = False,
        alias: str | None = None,
        auto_accept: bool | None = None,
        metadata: dict | None = None,
    ) -> OobCreateInvitationResponse:
        """
        Create an out-of-band invitation for either ephemeral or persistent connections.
        """
        logger.debug(">>> create_connection_invitation")

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

        resp = await self._http_client.post(
            self.acapy_host + OOB_CREATE_INVITATION,
            headers=await self.agent_config.get_headers(),
            json=create_invitation_payload,
            params=params,
        )

        assert resp.status_code == 200, resp.content

        result = OobCreateInvitationResponse.model_validate(resp.json())

        logger.debug("<<< create_connection_invitation")
        return result
