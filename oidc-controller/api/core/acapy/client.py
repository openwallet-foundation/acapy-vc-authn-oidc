import json
from uuid import UUID

import requests
import structlog

from ..config import settings
from .config import AgentConfig, MultiTenantAcapy, SingleTenantAcapy
from .models import CreatePresentationResponse, OobCreateInvitationResponse, WalletDid

_client = None
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

    wallet_token: str | None = None
    agent_config: AgentConfig

    def __init__(self):
        if settings.ACAPY_TENANCY == "multi":
            self.agent_config = MultiTenantAcapy()
        elif settings.ACAPY_TENANCY == "single":
            self.agent_config = SingleTenantAcapy()
        else:
            logger.warning("ACAPY_TENANCY not set, assuming SingleTenantAcapy")
            self.agent_config = SingleTenantAcapy()

        if _client:
            return _client
        super().__init__()

    def create_presentation_request(
        self, presentation_request_configuration: dict
    ) -> CreatePresentationResponse:
        logger.debug(">>> create_presentation_request")
        present_proof_payload = {
            "presentation_request": {"indy": presentation_request_configuration}
        }

        resp_raw = requests.post(
            self.acapy_host + CREATE_PRESENTATION_REQUEST_URL,
            headers=self.agent_config.get_headers(),
            json=present_proof_payload,
        )

        # TODO: Determine if this should assert it received a json object
        assert resp_raw.status_code == 200, resp_raw.content

        resp = json.loads(resp_raw.content)
        result = CreatePresentationResponse.model_validate(resp)

        logger.debug("<<< create_presenation_request")
        return result

    def get_presentation_request(self, presentation_exchange_id: UUID | str):
        logger.debug(">>> get_presentation_request")

        resp_raw = requests.get(
            self.acapy_host
            + PRESENT_PROOF_RECORDS
            + "/"
            + str(presentation_exchange_id),
            headers=self.agent_config.get_headers(),
        )

        # TODO: Determine if this should assert it received a json object
        assert resp_raw.status_code == 200, resp_raw.content

        resp = json.loads(resp_raw.content)

        logger.debug(f"<<< get_presentation_request -> {resp}")
        return resp

    def delete_presentation_record(self, presentation_exchange_id: UUID | str) -> bool:
        """Delete a presentation record by ID"""
        logger.debug(f">>> delete_presentation_record: {presentation_exchange_id}")

        try:
            resp_raw = requests.delete(
                f"{self.acapy_host}{PRESENT_PROOF_RECORDS}/{presentation_exchange_id}",
                headers=self.agent_config.get_headers(),
            )

            success = resp_raw.status_code == 200
            if success:
                logger.debug(f"<<< delete_presentation_record -> Success")
            else:
                logger.warning(
                    f"<<< delete_presentation_record -> Failed: {resp_raw.status_code}, {resp_raw.content}"
                )
            return success

        except Exception as e:
            logger.error(
                f"Failed to delete presentation record {presentation_exchange_id}: {e}"
            )
            return False

    def get_all_presentation_records(self) -> list[dict]:
        """Get all presentation records for cleanup purposes"""
        logger.debug(">>> get_all_presentation_records")

        try:
            resp_raw = requests.get(
                f"{self.acapy_host}{PRESENT_PROOF_RECORDS}",
                headers=self.agent_config.get_headers(),
            )

            if resp_raw.status_code != 200:
                logger.warning(
                    f"Failed to get presentation records: {resp_raw.status_code}, {resp_raw.content}"
                )
                return []

            resp = json.loads(resp_raw.content)
            records = resp.get("results", [])
            logger.debug(f"<<< get_all_presentation_records -> {len(records)} records")
            return records

        except Exception as e:
            logger.error(f"Failed to get all presentation records: {e}")
            return []

    def get_wallet_did(self, public=False) -> WalletDid:
        logger.debug(">>> get_wallet_did")
        url = None
        if public:
            url = self.acapy_host + PUBLIC_WALLET_DID_URI
        else:
            url = self.acapy_host + WALLET_DID_URI

        resp_raw = requests.get(
            url,
            headers=self.agent_config.get_headers(),
        )

        # TODO: Determine if this should assert it received a json object
        assert (
            resp_raw.status_code == 200
        ), f"{resp_raw.status_code}::{resp_raw.content}"

        resp = json.loads(resp_raw.content)

        if public:
            resp_payload = resp["result"]
        else:
            resp_payload = resp["results"][0]

        did = WalletDid.model_validate(resp_payload)

        logger.debug(f"<<< get_wallet_did -> {did}")
        return did

    def oob_create_invitation(
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

        resp_raw = requests.post(
            self.acapy_host + OOB_CREATE_INVITATION,
            headers=self.agent_config.get_headers(),
            json=create_invitation_payload,
        )

        assert resp_raw.status_code == 200, resp_raw.content

        resp = json.loads(resp_raw.content)
        result = OobCreateInvitationResponse.model_validate(resp)

        logger.debug("<<< oob_create_invitation")
        return result

    def send_presentation_request_by_connection(
        self, connection_id: str, presentation_request_configuration: dict
    ) -> CreatePresentationResponse:
        """
        Send a presentation request to an existing connection.

        Args:
            connection_id: The ID of the established connection
            presentation_request_configuration: The presentation request configuration

        Returns:
            CreatePresentationResponse: The response containing presentation exchange details
        """
        logger.debug(">>> send_presentation_request_by_connection")

        present_proof_payload = {
            "connection_id": connection_id,
            "presentation_request": {"indy": presentation_request_configuration},
        }

        resp_raw = requests.post(
            self.acapy_host + SEND_PRESENTATION_REQUEST_URL,
            headers=self.agent_config.get_headers(),
            json=present_proof_payload,
        )

        assert resp_raw.status_code == 200, resp_raw.content

        resp = json.loads(resp_raw.content)
        result = CreatePresentationResponse.model_validate(resp)

        logger.debug("<<< send_presentation_request_by_connection")
        return result

    def get_connection(self, connection_id: str) -> dict:
        """
        Get details of a specific connection.

        Args:
            connection_id: The ID of the connection to retrieve

        Returns:
            dict: Connection details
        """
        logger.debug(">>> get_connection")

        resp_raw = requests.get(
            self.acapy_host + CONNECTIONS_URI + "/" + connection_id,
            headers=self.agent_config.get_headers(),
        )

        assert resp_raw.status_code == 200, resp_raw.content

        resp = json.loads(resp_raw.content)
        logger.debug(f"<<< get_connection -> {resp}")
        return resp

    def list_connections(self, state: str | None = None) -> list[dict]:
        """
        List all connections, optionally filtered by state.

        Args:
            state: Optional state filter (e.g., "active", "completed")

        Returns:
            list[dict]: List of connection records
        """
        logger.debug(">>> list_connections")

        params = {}
        if state:
            params["state"] = state

        resp_raw = requests.get(
            self.acapy_host + CONNECTIONS_URI,
            headers=self.agent_config.get_headers(),
            params=params,
        )

        assert resp_raw.status_code == 200, resp_raw.content

        resp = json.loads(resp_raw.content)
        connections = resp.get("results", [])

        logger.debug(f"<<< list_connections -> {len(connections)} connections")
        return connections

    def _get_connections_page(
        self, state: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[dict]:
        """
        Get a page of connections with pagination support.

        Args:
            state: Optional state filter (e.g., "invitation", "active")
            limit: Maximum number of connections to return
            offset: Number of connections to skip

        Returns:
            list[dict]: List of connection records for this page
        """
        logger.debug(
            f">>> _get_connections_page: state={state}, limit={limit}, offset={offset}"
        )

        params = {}
        if state:
            params["state"] = state

        # Try pagination parameters (may not be supported by all ACA-Py versions)
        params["limit"] = limit
        params["offset"] = offset

        try:
            resp_raw = requests.get(
                self.acapy_host + CONNECTIONS_URI,
                headers=self.agent_config.get_headers(),
                params=params,
            )

            if resp_raw.status_code != 200:
                logger.warning(
                    f"Failed to get connections page: {resp_raw.status_code}"
                )
                return []

            resp = json.loads(resp_raw.content)
            connections = resp.get("results", [])

            logger.debug(f"<<< _get_connections_page -> {len(connections)} connections")
            return connections

        except Exception as e:
            logger.error(f"Error getting connections page: {e}")
            return []

    def get_connections_batched(self, state: str = "invitation", batch_size: int = 100):
        """
        Get connections in batches using iterator pattern for memory efficiency.

        Args:
            state: State filter for connections (default: "invitation")
            batch_size: Number of connections per batch (default: 100)

        Yields:
            list[dict]: Batches of connection records
        """
        logger.debug(
            f">>> get_connections_batched: state={state}, batch_size={batch_size}"
        )

        offset = 0
        total_yielded = 0

        while True:
            batch = self._get_connections_page(state, batch_size, offset)

            if not batch:  # No more results
                break

            total_yielded += len(batch)
            logger.debug(
                f"Yielding batch of {len(batch)} connections (total so far: {total_yielded})"
            )
            yield batch

            # If we got less than batch_size, we've reached the end
            if len(batch) < batch_size:
                break

            offset += batch_size

        logger.debug(
            f"<<< get_connections_batched -> yielded {total_yielded} total connections"
        )

    def get_all_connections(self) -> list[dict]:
        """Get all connections for cleanup purposes"""
        logger.debug(">>> get_all_connections")

        try:
            resp_raw = requests.get(
                f"{self.acapy_host}{CONNECTIONS_URI}",
                headers=self.agent_config.get_headers(),
            )

            if resp_raw.status_code != 200:
                logger.warning(
                    f"Failed to get connections: {resp_raw.status_code}, {resp_raw.content}"
                )
                return []

            resp = json.loads(resp_raw.content)
            connections = resp.get("results", [])

            logger.debug(f"<<< get_all_connections -> {len(connections)} connections")
            return connections

        except Exception as e:
            logger.error(f"Error getting all connections: {e}")
            return []

    def delete_connection(self, connection_id: str) -> bool:
        """
        Delete a connection.

        Args:
            connection_id: The ID of the connection to delete

        Returns:
            bool: True if deletion was successful
        """
        logger.debug(">>> delete_connection")

        try:
            resp_raw = requests.delete(
                self.acapy_host + CONNECTIONS_URI + "/" + connection_id,
                headers=self.agent_config.get_headers(),
            )

            success = resp_raw.status_code == 200
            if success:
                logger.debug(f"<<< delete_connection -> Success")
            else:
                logger.warning(
                    f"<<< delete_connection -> Failed: {resp_raw.status_code}, {resp_raw.content}"
                )
            return success

        except Exception as e:
            logger.error(f"Failed to delete connection {connection_id}: {e}")
            return False

    def delete_presentation_record_and_connection(
        self, presentation_exchange_id: UUID | str, connection_id: str | None = None
    ) -> tuple[bool, bool | None, list[str]]:
        """
        Delete a presentation record and optionally its associated connection.

        This is the recommended method for cleanup as it handles both the presentation
        record and connection deletion in the proper order.

        Args:
            presentation_exchange_id: The presentation exchange ID to delete
            connection_id: Optional connection ID to delete. If not provided,
                         only the presentation record will be deleted.

        Returns:
            tuple[bool, bool | None, list[str]]: A tuple containing:
                - presentation_deleted: bool - True if presentation record was successfully deleted
                - connection_deleted: bool | None - True/False if connection deletion was attempted, None if not
                - errors: list[str] - List of error messages from failed operations
        """
        logger.debug(
            f">>> delete_presentation_record_and_connection: pres_ex={presentation_exchange_id}, conn={connection_id}"
        )

        presentation_deleted = False
        connection_deleted = None
        errors = []

        # First, delete the presentation record
        if presentation_exchange_id:
            try:
                presentation_deleted = self.delete_presentation_record(
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

        # Second, delete the connection if provided
        # TODO: make mandatory when we drop OOB
        if connection_id:
            try:
                connection_deleted = self.delete_connection(connection_id)

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

    def send_problem_report(self, pres_ex_id: str, description: str) -> bool:
        """
        Send a problem report for a presentation exchange.

        Args:
            pres_ex_id: The presentation exchange ID
            description: Description of the problem

        Returns:
            bool: True if problem report was sent successfully
        """
        logger.debug(">>> send_problem_report")

        problem_report_payload = {"description": description}

        try:
            resp_raw = requests.post(
                self.acapy_host
                + PRESENT_PROOF_PROBLEM_REPORT_URL.format(pres_ex_id=pres_ex_id),
                json=problem_report_payload,
                headers=self.agent_config.get_headers(),
            )

            success = resp_raw.status_code == 200
            logger.debug(f"<<< send_problem_report -> {success}")

            if not success:
                logger.error(
                    f"Failed to send problem report: {resp_raw.status_code} - {resp_raw.content}"
                )

            return success

        except Exception as e:
            logger.error(f"Error sending problem report: {e}")
            return False

    def create_connection_invitation(
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

        Args:
            multi_use: Whether this is an non ephemeral (multi_use) connection (default: False)
            presentation_exchange: Optional presentation exchange to attach to invitation
            use_public_did: Whether to use public DID for the invitation (default: False)
            alias: Optional alias for the connection (default: None)
            auto_accept: Whether to auto-accept the connection (default: None - use configuration)
            metadata: Optional metadata to attach to the connection (default: None)

        Returns:
            OobCreateInvitationResponse: The response containing invitation details
        """
        logger.debug(">>> create_connection_invitation")

        # Determine connection type and goal code
        if multi_use:
            goal_code = "aries.vc.verify"
            goal = "Verify credentials for authentication"
            multi_use = True
        else:
            goal_code = "aries.vc.verify.once"
            goal = "Verify credentials for single-use authentication"
            multi_use = False
        # Prepare the payload for the invitation creation
        create_invitation_payload = {
            "use_public_did": use_public_did,
            "my_label": settings.INVITATION_LABEL,
            "goal_code": goal_code,
            "goal": goal,
        }

        # Add handshake protocols if no presentation attachment is provided
        if not presentation_exchange:
            create_invitation_payload["handshake_protocols"] = [
                "https://didcomm.org/didexchange/1.0",
                "https://didcomm.org/connections/1.0",
            ]

        # Add presentation exchange attachment if provided
        if presentation_exchange:
            create_invitation_payload["attachments"] = [
                {
                    "id": presentation_exchange["pres_ex_id"],
                    "type": "present-proof",
                    "data": {"json": presentation_exchange},
                }
            ]

        # Add optional body parameters if provided
        if alias is not None:
            create_invitation_payload["alias"] = alias
        if metadata:
            create_invitation_payload["metadata"] = metadata

        # Prepare query parameters
        params = {"multi_use": str(multi_use).lower()}
        if auto_accept is not None:
            params["auto_accept"] = str(auto_accept).lower()

        # Make the request to ACA-Py
        resp_raw = requests.post(
            self.acapy_host + OOB_CREATE_INVITATION,
            headers=self.agent_config.get_headers(),
            json=create_invitation_payload,
            params=params,
        )

        # Validate the response
        assert resp_raw.status_code == 200, resp_raw.content

        # Parse and validate the response
        resp = json.loads(resp_raw.content)
        result = OobCreateInvitationResponse.model_validate(resp)

        logger.debug("<<< create_connection_invitation")
        return result
