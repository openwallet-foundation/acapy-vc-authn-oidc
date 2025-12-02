#!/usr/bin/env python3
"""
Bootstrap script for issuing trusted verifier credential.

This script:
1. Creates a connection between issuer and verifier agents
2. Creates schema and credential definition on issuer
3. Issues trusted verifier credential from issuer to verifier

Usage:
    cd docker && LEDGER_URL=http://test.bcovrin.vonx.io ... ./manage bootstrap
For Testing Credential:
    cd docker && TEST_PROVER_ROLE=true LEDGER_URL=http://test.bcovrin.vonx.io ... ./manage bootstrap
"""

import os
import sys
import time
import requests
from typing import Optional, Dict, Any
import random
import string


def generate_random_string(length=12):
    characters = string.ascii_letters + string.digits
    random_string = "".join(random.choice(characters) for _ in range(length))
    return random_string


# Configuration
ISSUER_ADMIN_URL = os.getenv("ISSUER_ADMIN_URL", "http://localhost:8078")
VERIFIER_ADMIN_URL = os.getenv("VERIFIER_ADMIN_URL", "http://localhost:8077")
VERIFIER_ADMIN_API_KEY = os.getenv("VERIFIER_ADMIN_API_KEY", "")

SCHEMA_NAME = os.getenv("VERIFIER_SCHEMA_NAME", "verifier_schema")
SCHEMA_VERSION = os.getenv("VERIFIER_SCHEMA_VERSION", "1.0")
SCHEMA_ATTRIBUTES = os.getenv(
    "VERIFIER_SCHEMA_ATTRIBUTES",
    "verifier_name,authorized_scopes,issue_date,issuer_name",
).split(",")

# Credential values
CREDENTIAL_VALUES = {
    "verifier_name": os.getenv("VERIFIER_NAME", "VC-AuthN Dev Instance"),
    "authorized_scopes": os.getenv("AUTHORIZED_SCOPES", "health,education,government"),
    "issue_date": time.strftime("%Y-%m-%d"),
    "issuer_name": os.getenv("ISSUER_NAME", "Trusted Verifier Issuer"),
}

# Prover-role testing configuration
TEST_PROVER_ROLE = os.getenv("TEST_PROVER_ROLE", "false").lower() == "true"


def log(message: str):
    """Print timestamped log message."""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def wait_for_agent(url: str, timeout: int = 60) -> bool:
    """Wait for agent to be ready."""
    log(f"Waiting for agent at {url}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = requests.get(f"{url}/status", timeout=5)
            if response.status_code == 200:
                log(f"Agent at {url} is ready!")
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
    log(f"Timeout waiting for agent at {url}")
    return False


def make_request(
    method: str,
    url: str,
    json_data: Optional[Dict] = None,
    api_key: Optional[str] = None,
    params: Optional[Dict] = None,
) -> Dict[Any, Any]:
    """Make HTTP request to agent admin API."""
    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        response = requests.request(
            method, url, json=json_data, headers=headers, params=params, timeout=30
        )
        response.raise_for_status()
        return response.json() if response.content else {}
    except requests.exceptions.RequestException as e:
        log(f"Request failed: {e}")
        if hasattr(e, "response") and e.response is not None:
            log(f"Response: {e.response.text}")
        raise


def get_public_did() -> Optional[str]:
    """Check if issuer has a public DID."""
    log("Checking for public DID...")
    try:
        result = make_request("GET", f"{ISSUER_ADMIN_URL}/wallet/did/public")
        public_did = result.get("result", {}).get("did")
        if public_did:
            log(f"Found existing public DID: {public_did}")
            return public_did
    except Exception:
        pass
    return None


def register_public_did():
    """Register public DID on BCovrin Test ledger."""
    log("Registering public DID on BCovrin Test ledger...")

    # Get local DID
    result = make_request("GET", f"{ISSUER_ADMIN_URL}/wallet/did")
    dids = result.get("results", [])
    if not dids:
        raise Exception("No local DID found in wallet")

    local_did = dids[0]["did"]
    verkey = dids[0]["verkey"]
    log(f"Local DID: {local_did}")

    # Register on BCovrin Test ledger
    ledger_url = "http://test.bcovrin.vonx.io/register"
    payload = {
        "did": local_did,
        "verkey": verkey,
        "alias": "Trusted Verifier Issuer",
        "role": "ENDORSER",
    }

    log(f"Registering DID on ledger: {ledger_url}")
    try:
        response = requests.post(ledger_url, json=payload, timeout=30)
        response.raise_for_status()
        log("DID registered successfully on ledger")
    except requests.exceptions.RequestException as e:
        log(f"Warning: Ledger registration failed: {e}")
        log("Attempting to set as public DID anyway...")

    # Set as public DID in agent
    time.sleep(3)  # Give ledger time to process
    result = make_request(
        "POST", f"{ISSUER_ADMIN_URL}/wallet/did/public", json_data={"did": local_did}
    )
    log(f"Set public DID: {result.get('result', {}).get('did')}")
    return local_did


def accept_taa():
    """Accept Transaction Author Agreement if required."""
    log("Checking for Transaction Author Agreement...")
    try:
        result = make_request("GET", f"{ISSUER_ADMIN_URL}/ledger/taa")
        taa = result.get("result", {}).get("taa_record")
        if taa:
            log("TAA found, accepting...")
            taa_accept = {
                "version": taa.get("version"),
                "text": taa.get("text"),
                "mechanism": "service_agreement",
            }
            make_request(
                "POST", f"{ISSUER_ADMIN_URL}/ledger/taa/accept", json_data=taa_accept
            )
            log("TAA accepted")
    except Exception as e:
        log(f"TAA check/accept: {e}")


def find_existing_schema(schema_name: str, schema_version: str) -> Optional[str]:
    """Check if schema already exists."""
    log(f"Checking for existing schema: {schema_name} v{schema_version}")
    try:
        result = make_request("GET", f"{ISSUER_ADMIN_URL}/schemas/created")
        schema_ids = result.get("schema_ids", [])

        for schema_id in schema_ids:
            if schema_name in schema_id and schema_version in schema_id:
                log(f"Found existing schema: {schema_id}")
                return schema_id
    except Exception as e:
        log(f"Error checking for existing schema: {e}")
    return None


def create_schema() -> str:
    """Create schema on ledger."""
    # Check if schema already exists
    existing_schema_id = find_existing_schema(SCHEMA_NAME, SCHEMA_VERSION)
    if existing_schema_id:
        return existing_schema_id

    log(f"Creating schema: {SCHEMA_NAME} v{SCHEMA_VERSION}")
    payload = {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "attributes": SCHEMA_ATTRIBUTES,
    }
    result = make_request("POST", f"{ISSUER_ADMIN_URL}/schemas", json_data=payload)
    schema_id = result.get("sent", {}).get("schema_id")
    log(f"Created schema: {schema_id}")
    return schema_id


def find_existing_cred_def(schema_id: str) -> Optional[str]:
    """Check if cred def already exists for schema."""
    log(f"Checking for existing cred def for schema: {schema_id}")
    try:
        # Use schema_id query parameter to filter results
        result = make_request(
            "GET",
            f"{ISSUER_ADMIN_URL}/credential-definitions/created",
            params={"schema_id": schema_id},
        )
        cred_def_ids = result.get("credential_definition_ids", [])

        # Return first cred def with "default" tag
        for cred_def_id in cred_def_ids:
            if ":default" in cred_def_id:
                log(f"Found existing cred def: {cred_def_id}")
                return cred_def_id
    except Exception as e:
        log(f"Error checking for existing cred def: {e}")
    return None


def create_cred_def(schema_id: str) -> str:
    """Create credential definition."""
    # Check if cred def already exists
    existing_cred_def_id = find_existing_cred_def(schema_id)
    if existing_cred_def_id:
        return existing_cred_def_id

    log(f"Creating credential definition for schema: {schema_id}")
    payload = {"schema_id": schema_id, "tag": "default", "support_revocation": False}

    try:
        result = make_request(
            "POST", f"{ISSUER_ADMIN_URL}/credential-definitions", json_data=payload
        )
        cred_def_id = result.get("sent", {}).get("credential_definition_id")
        log(f"Created cred def: {cred_def_id}")
        time.sleep(5)  # Give ledger time to process
        return cred_def_id
    except requests.exceptions.RequestException as e:
        # If it already exists, construct expected ID and verify on ledger
        if "already exists" in str(e).lower():
            log("Cred def already exists (detected from error), verifying on ledger...")

            # Construct expected cred_def_id
            # Format: {issuer_did}:3:CL:{schema_seqno}:{tag}
            parts = schema_id.split(":")
            issuer_did = parts[0]
            expected_cred_def_id = f"{issuer_did}:3:CL:{schema_id}:default"
            log(f"Expected cred_def_id: {expected_cred_def_id}")

            # Verify it exists on ledger
            try:
                result = make_request(
                    "GET",
                    f"{ISSUER_ADMIN_URL}/credential-definitions/{expected_cred_def_id}",
                )
                if result.get("credential_definition"):
                    log(f"Verified cred def exists on ledger: {expected_cred_def_id}")
                    return expected_cred_def_id
            except Exception as ledger_error:
                log(f"Could not verify cred def on ledger: {ledger_error}")

            # Fallback: try to find it in created list
            time.sleep(2)
            existing_cred_def_id = find_existing_cred_def(schema_id)
            if existing_cred_def_id:
                return existing_cred_def_id

            raise Exception(
                f"Cred def exists but could not be found. Expected: {expected_cred_def_id}"
            )
        raise


def create_connection() -> tuple[str, str]:
    """Create connection between issuer and verifier."""
    log("Creating connection between issuer and verifier...")

    # Create out-of-band invitation from issuer
    payload = {
        "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
        "use_public_did": False,
        "auto_accept": True,
    }
    result = make_request(
        "POST", f"{ISSUER_ADMIN_URL}/out-of-band/create-invitation", json_data=payload
    )
    invitation = result.get("invitation")
    issuer_oob_id = result.get("invi_msg_id")
    log(f"Created OOB invitation from issuer (invi_msg_id: {issuer_oob_id})")

    # Verifier receives invitation
    result = make_request(
        "POST",
        f"{VERIFIER_ADMIN_URL}/out-of-band/receive-invitation",
        json_data=invitation,
        api_key=VERIFIER_ADMIN_API_KEY,
        params={"auto_accept": "true"},
    )
    verifier_conn_id = result.get("connection_id")
    log(f"Verifier received invitation (conn_id: {verifier_conn_id})")

    # Find issuer's connection ID by matching invitation_msg_id
    log("Finding issuer connection ID...")
    issuer_conn_id = None
    for attempt in range(15):
        time.sleep(1)
        result = make_request("GET", f"{ISSUER_ADMIN_URL}/connections")
        connections = result.get("results", [])

        # Find connection matching this invitation
        for conn in connections:
            if conn.get("invitation_msg_id") == issuer_oob_id:
                issuer_conn_id = conn.get("connection_id")
                state = conn.get("state")
                log(
                    f"Found issuer connection (attempt {attempt + 1}): {issuer_conn_id}, state: {state}"
                )
                break

        if issuer_conn_id:
            break

    if not issuer_conn_id:
        raise Exception("Could not find issuer connection ID")

    log(f"Issuer connection ID: {issuer_conn_id}")

    # Wait for connection to be active
    log("Waiting for connection to become active...")
    for _ in range(30):
        result = make_request("GET", f"{ISSUER_ADMIN_URL}/connections/{issuer_conn_id}")
        state = result.get("state")
        if state == "active":
            log("Connection is active!")
            return issuer_conn_id, verifier_conn_id
        time.sleep(1)

    raise Exception("Connection did not become active in time")


def issue_credential(connection_id: str, cred_def_id: str):
    """Issue trusted verifier credential."""
    log("Issuing trusted verifier credential...")

    attributes = [
        {"name": name, "value": value} for name, value in CREDENTIAL_VALUES.items()
    ]

    payload = {
        "auto_issue": True,
        "auto_remove": False,
        "connection_id": connection_id,
        "credential_preview": {
            "@type": "issue-credential/2.0/credential-preview",
            "attributes": attributes,
        },
        "filter": {"indy": {"cred_def_id": cred_def_id}},
    }

    result = make_request(
        "POST", f"{ISSUER_ADMIN_URL}/issue-credential-2.0/send-offer", json_data=payload
    )
    cred_ex_id = result.get("cred_ex_id")
    log(f"Sent credential offer (cred_ex_id: {cred_ex_id})")

    # Wait for credential to be issued
    log("Waiting for credential to be issued and stored...")
    for _ in range(30):
        result = make_request(
            "GET", f"{ISSUER_ADMIN_URL}/issue-credential-2.0/records/{cred_ex_id}"
        )
        state = result.get("cred_ex_record", {}).get("state")
        log(f"Credential exchange state: {state}")
        if state == "done":
            log("Credential successfully issued and stored!")
            return
        time.sleep(2)

    raise Exception("Credential was not issued in time")


def verify_credential_in_wallet(cred_def_id: str) -> bool:
    """Verify credential exists in verifier wallet."""
    log("Verifying credential in verifier wallet...")
    try:
        result = make_request(
            "GET", f"{VERIFIER_ADMIN_URL}/credentials", api_key=VERIFIER_ADMIN_API_KEY
        )
        results = result.get("results", [])
        for cred in results:
            if cred.get("cred_def_id") == cred_def_id:
                log(f"✓ Credential found in wallet: {cred.get('referent')}")
                return True
        log("✗ Credential not found in wallet")
        return False
    except Exception as e:
        log(f"Error verifying credential: {e}")
        return False


# ============================================================================
# PROVER-ROLE TESTING FUNCTIONS (for issue #898)
# These functions test VC-AuthN acting as a prover responding to proof requests
# ============================================================================


def send_proof_request(connection_id: str, cred_def_id: str) -> str:
    """Send proof request from issuer to VC-AuthN (prover role test).

    Args:
        connection_id: Issuer's connection ID to VC-AuthN
        cred_def_id: Credential definition to request proof for

    Returns:
        Presentation exchange ID
    """
    log("PROVER-ROLE TEST: Sending proof request to VC-AuthN...")

    # Build proof request for trusted verifier credential
    proof_request = {
        "comment": "Proof request for testing VC-AuthN prover role (issue #898)",
        "connection_id": connection_id,
        "presentation_request": {
            "indy": {
                "name": "Trusted Verifier Proof Request",
                "version": "1.0",
                "requested_attributes": {
                    "verifier_name": {
                        "name": "verifier_name",
                        "restrictions": [{"cred_def_id": cred_def_id}],
                    },
                    "authorized_scopes": {
                        "name": "authorized_scopes",
                        "restrictions": [{"cred_def_id": cred_def_id}],
                    },
                },
                "requested_predicates": {},
            }
        },
        "auto_verify": True,
        "auto_remove": False,
    }

    result = make_request(
        "POST",
        f"{ISSUER_ADMIN_URL}/present-proof-2.0/send-request",
        json_data=proof_request,
    )
    pres_ex_id = result.get("pres_ex_id")
    log(f"PROVER-ROLE TEST: Sent proof request (pres_ex_id: {pres_ex_id})")
    return pres_ex_id


def verify_proof_presentation(pres_ex_id: str) -> bool:
    """Verify presentation exchange completes successfully.

    Args:
        pres_ex_id: Presentation exchange ID

    Returns:
        True if presentation verified successfully
    """
    log("PROVER-ROLE TEST: Waiting for VC-AuthN to respond with presentation...")

    for attempt in range(30):
        result = make_request(
            "GET", f"{ISSUER_ADMIN_URL}/present-proof-2.0/records/{pres_ex_id}"
        )
        state = result.get("state")
        verified = result.get("verified")

        log(
            f"PROVER-ROLE TEST: Presentation state: {state}, verified: {verified} (attempt {attempt + 1})"
        )

        if state == "done":
            if verified == "true":
                log("PROVER-ROLE TEST: ✓ Presentation verified successfully!")
                return True
            else:
                log(
                    f"PROVER-ROLE TEST: ✗ Presentation not verified (verified={verified})"
                )
                return False

        time.sleep(2)

    log("PROVER-ROLE TEST: ✗ Presentation did not complete in time")
    return False


def test_prover_role(issuer_conn_id: str, cred_def_id: str) -> bool:
    """Test VC-AuthN acting as prover by sending proof request.

    This tests the webhook logging functionality for issue #898.

    Args:
        issuer_conn_id: Issuer's connection ID to VC-AuthN
        cred_def_id: Credential definition to request proof for

    Returns:
        True if prover-role test passed
    """
    log("=" * 60)
    log("PROVER-ROLE TEST: Starting (issue #898)")
    log("=" * 60)

    try:
        pres_ex_id = send_proof_request(issuer_conn_id, cred_def_id)
        success = verify_proof_presentation(pres_ex_id)

        log("=" * 60)
        if success:
            log("PROVER-ROLE TEST: ✓ SUCCESS")
            log(
                "Check controller logs for prover-role webhook events with role='prover'"
            )
        else:
            log("PROVER-ROLE TEST: ✗ FAILED")
        log("=" * 60)

        return success

    except Exception as e:
        log(f"PROVER-ROLE TEST: ✗ Error: {e}")
        return False


def main():
    """Main bootstrap process."""
    log("=" * 60)
    log("Bootstrap Trusted Verifier Credential")
    log("=" * 60)

    try:
        # Step 1: Wait for agents
        if not wait_for_agent(ISSUER_ADMIN_URL):
            log("ERROR: Issuer agent not ready")
            sys.exit(1)
        if not wait_for_agent(VERIFIER_ADMIN_URL):
            log("ERROR: Verifier agent not ready")
            sys.exit(1)

        # Step 2: Setup issuer public DID
        public_did = get_public_did()
        if not public_did:
            public_did = register_public_did()
            accept_taa()

        # Step 3: Create schema and cred def
        schema_id = create_schema()
        cred_def_id = create_cred_def(schema_id)

        # Step 4: Create connection
        issuer_conn_id, verifier_conn_id = create_connection()

        # Step 5: Issue credential
        issue_credential(issuer_conn_id, cred_def_id)

        # Step 6: Verify
        if verify_credential_in_wallet(cred_def_id):
            log("=" * 60)
            log("SUCCESS: Trusted verifier credential bootstrap complete!")
            log("=" * 60)
            log(f"Schema ID: {schema_id}")
            log(f"Cred Def ID: {cred_def_id}")
            log(f"Connection ID (Issuer): {issuer_conn_id}")
            log("=" * 60)
        else:
            log("WARNING: Bootstrap completed but credential not found in wallet")
            sys.exit(1)

        # Step 7: Optional prover-role testing (issue #898)
        if TEST_PROVER_ROLE:
            log("")
            log("TEST_PROVER_ROLE=true detected, running prover-role test...")
            if not test_prover_role(issuer_conn_id, cred_def_id):
                log("ERROR: Prover-role test failed")
                sys.exit(1)

    except Exception as e:
        log(f"ERROR: Bootstrap failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
