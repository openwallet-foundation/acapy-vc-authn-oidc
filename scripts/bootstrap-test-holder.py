#!/usr/bin/env python3
"""
Bootstrap script for E2E tests: issue a test credential to the holder agent.

This script:
1. Waits for both issuer and holder ACA-Py agents to be ready
2. Registers the issuer DID on BCovrin Test ledger
3. Creates a test schema and credential definition (idempotent)
4. Establishes a connection between issuer and holder
5. Issues a test credential with first_name/last_name attributes to the holder
6. Writes output (cred_def_id, schema_id) to tests/e2e/bootstrap_output.json

Usage:
    ISSUER_ADMIN_URL=http://localhost:8078 \
    HOLDER_ADMIN_URL=http://localhost:8079 \
    python scripts/bootstrap-test-holder.py
"""

import json
import os
import sys
import time
import requests
from pathlib import Path
from typing import Optional, Dict, Any


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ISSUER_ADMIN_URL = os.getenv("ISSUER_ADMIN_URL", "http://localhost:8078")
HOLDER_ADMIN_URL = os.getenv("HOLDER_ADMIN_URL", "http://localhost:8079")
LEDGER_URL = os.getenv("LEDGER_URL", "http://test.bcovrin.vonx.io/register")

SCHEMA_NAME = os.getenv("E2E_SCHEMA_NAME", "e2e_test_credential")
SCHEMA_VERSION = os.getenv("E2E_SCHEMA_VERSION", "1.0")
SCHEMA_ATTRIBUTES = ["first_name", "last_name"]

CREDENTIAL_VALUES = {
    "first_name": os.getenv("E2E_HOLDER_FIRST_NAME", "Alice"),
    "last_name": os.getenv("E2E_HOLDER_LAST_NAME", "Smith"),
}

OUTPUT_FILE = Path(__file__).parent.parent / "tests" / "e2e" / "bootstrap_output.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def make_request(
    method: str,
    url: str,
    json_data: Optional[Dict] = None,
    params: Optional[Dict] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    response = requests.request(
        method, url, json=json_data, params=params, timeout=timeout
    )
    response.raise_for_status()
    return response.json() if response.content else {}


def wait_for_agent(url: str, timeout: int = 120) -> bool:
    log(f"Waiting for agent at {url}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{url}/status", timeout=5)
            if r.status_code == 200:
                log(f"Agent ready: {url}")
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(3)
    log(f"Timeout waiting for agent: {url}")
    return False


# ---------------------------------------------------------------------------
# Issuer DID setup
# ---------------------------------------------------------------------------


def get_or_register_public_did() -> str:
    """Return existing public DID or register a new one on the ledger."""
    result = make_request("GET", f"{ISSUER_ADMIN_URL}/wallet/did/public")
    existing = result.get("result", {}).get("did")
    if existing:
        log(f"Issuer already has public DID: {existing}")
        return existing

    log("Registering issuer DID on BCovrin Test ledger...")
    dids = make_request("GET", f"{ISSUER_ADMIN_URL}/wallet/did").get("results", [])
    if not dids:
        raise RuntimeError("No local DID found in issuer wallet")

    did = dids[0]["did"]
    verkey = dids[0]["verkey"]
    log(f"Local DID: {did}")

    try:
        requests.post(
            LEDGER_URL,
            json={
                "did": did,
                "verkey": verkey,
                "alias": "E2E Test Issuer",
                "role": "ENDORSER",
            },
            timeout=30,
        ).raise_for_status()
        log("DID registered on ledger")
    except requests.exceptions.RequestException as e:
        log(f"Ledger registration warning (continuing): {e}")

    time.sleep(3)
    make_request(
        "POST", f"{ISSUER_ADMIN_URL}/wallet/did/public", json_data={"did": did}
    )
    log(f"Set public DID: {did}")
    return did


def accept_taa() -> None:
    try:
        result = make_request("GET", f"{ISSUER_ADMIN_URL}/ledger/taa")
        taa = result.get("result", {}).get("taa_record")
        if taa:
            make_request(
                "POST",
                f"{ISSUER_ADMIN_URL}/ledger/taa/accept",
                json_data={
                    "version": taa["version"],
                    "text": taa["text"],
                    "mechanism": "service_agreement",
                },
            )
            log("TAA accepted")
    except Exception as e:
        log(f"TAA check skipped: {e}")


# ---------------------------------------------------------------------------
# Schema and credential definition
# ---------------------------------------------------------------------------


def get_or_create_schema() -> str:
    log(f"Looking for existing schema: {SCHEMA_NAME} v{SCHEMA_VERSION}")
    existing = make_request("GET", f"{ISSUER_ADMIN_URL}/schemas/created")
    for sid in existing.get("schema_ids", []):
        if SCHEMA_NAME in sid and SCHEMA_VERSION in sid:
            log(f"Using existing schema: {sid}")
            return sid

    log(f"Creating schema: {SCHEMA_NAME} v{SCHEMA_VERSION}")
    result = make_request(
        "POST",
        f"{ISSUER_ADMIN_URL}/schemas",
        json_data={
            "schema_name": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
            "attributes": SCHEMA_ATTRIBUTES,
        },
    )
    schema_id = result.get("sent", {}).get("schema_id") or result.get("schema_id")
    log(f"Created schema: {schema_id}")
    return schema_id


def get_or_create_cred_def(schema_id: str) -> str:
    log(f"Looking for existing cred def for schema: {schema_id}")
    existing = make_request(
        "GET",
        f"{ISSUER_ADMIN_URL}/credential-definitions/created",
        params={"schema_id": schema_id},
    )
    for cid in existing.get("credential_definition_ids", []):
        if ":default" in cid:
            log(f"Using existing cred def: {cid}")
            return cid

    log(f"Creating credential definition for schema: {schema_id}")
    result = make_request(
        "POST",
        f"{ISSUER_ADMIN_URL}/credential-definitions",
        json_data={
            "schema_id": schema_id,
            "tag": "default",
            "support_revocation": False,
        },
    )
    cred_def_id = result.get("sent", {}).get("credential_definition_id") or result.get(
        "credential_definition_id"
    )
    log(f"Created cred def: {cred_def_id}")
    time.sleep(5)  # Allow ledger to process
    return cred_def_id


# ---------------------------------------------------------------------------
# Connection between issuer and holder
# ---------------------------------------------------------------------------


def create_issuer_to_holder_connection() -> tuple[str, str]:
    """Create OOB connection: issuer creates invitation, holder receives it.

    Returns (issuer_connection_id, holder_connection_id).
    """
    log("Creating OOB invitation from issuer...")
    result = make_request(
        "POST",
        f"{ISSUER_ADMIN_URL}/out-of-band/create-invitation",
        json_data={
            "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
            "use_public_did": False,
            "auto_accept": True,
        },
    )
    invitation = result["invitation"]
    invi_msg_id = result["invi_msg_id"]
    log(f"Invitation created (invi_msg_id={invi_msg_id})")

    log("Holder receiving invitation...")
    holder_result = make_request(
        "POST",
        f"{HOLDER_ADMIN_URL}/out-of-band/receive-invitation",
        json_data=invitation,
        params={"auto_accept": "true"},
    )
    holder_conn_id = holder_result.get("connection_id")
    log(f"Holder connection: {holder_conn_id}")

    # Wait for connections to become active
    issuer_conn_id = _wait_for_active_connection(
        ISSUER_ADMIN_URL, invi_msg_id=invi_msg_id
    )
    _wait_for_connection_active(HOLDER_ADMIN_URL, holder_conn_id)
    return issuer_conn_id, holder_conn_id


def _wait_for_active_connection(
    admin_url: str, invi_msg_id: str, timeout: int = 60
) -> str:
    log(f"Waiting for active connection at {admin_url}...")
    start = time.time()
    while time.time() - start < timeout:
        conns = make_request("GET", f"{admin_url}/connections").get("results", [])
        for c in conns:
            if c.get("invitation_msg_id") == invi_msg_id and c.get("state") in (
                "active",
                "completed",
                "response",
            ):
                log(f"Connection active: {c['connection_id']}")
                return c["connection_id"]
        time.sleep(2)
    raise RuntimeError(f"Timeout waiting for active connection at {admin_url}")


def _wait_for_connection_active(
    admin_url: str, conn_id: str, timeout: int = 60
) -> None:
    log(f"Waiting for connection {conn_id} to become active...")
    start = time.time()
    while time.time() - start < timeout:
        result = make_request("GET", f"{admin_url}/connections/{conn_id}")
        if result.get("state") in ("active", "completed", "response"):
            log(f"Connection {conn_id} active")
            return
        time.sleep(2)
    raise RuntimeError(f"Timeout waiting for connection {conn_id}")


# ---------------------------------------------------------------------------
# Credential issuance
# ---------------------------------------------------------------------------


def issue_credential_to_holder(issuer_conn_id: str, cred_def_id: str) -> None:
    log(f"Issuing credential to holder via connection {issuer_conn_id}...")
    attributes = [{"name": k, "value": v} for k, v in CREDENTIAL_VALUES.items()]
    result = make_request(
        "POST",
        f"{ISSUER_ADMIN_URL}/issue-credential-2.0/send",
        json_data={
            "connection_id": issuer_conn_id,
            "credential_preview": {
                "@type": "issue-credential/2.0/credential-preview",
                "attributes": attributes,
            },
            "filter": {"indy": {"cred_def_id": cred_def_id}},
            "auto_remove": True,
        },
    )
    cred_ex_id = result.get("cred_ex_id") or result.get("credential_exchange_id")
    log(
        f"Credential offer sent (cred_ex_id={cred_ex_id}), waiting for holder to store..."
    )
    _wait_for_credential_in_holder_wallet()


def _wait_for_credential_in_holder_wallet(timeout: int = 90) -> None:
    start = time.time()
    while time.time() - start < timeout:
        creds = make_request("GET", f"{HOLDER_ADMIN_URL}/credentials").get(
            "results", []
        )
        if creds:
            log(f"Holder has {len(creds)} credential(s) in wallet")
            return
        time.sleep(3)
    raise RuntimeError("Timeout waiting for credential to appear in holder wallet")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    log("=== E2E Test Holder Bootstrap ===")

    if not wait_for_agent(ISSUER_ADMIN_URL):
        sys.exit(1)
    if not wait_for_agent(HOLDER_ADMIN_URL):
        sys.exit(1)

    accept_taa()
    get_or_register_public_did()
    schema_id = get_or_create_schema()
    cred_def_id = get_or_create_cred_def(schema_id)

    issuer_conn_id, _ = create_issuer_to_holder_connection()
    issue_credential_to_holder(issuer_conn_id, cred_def_id)

    output = {
        "cred_def_id": cred_def_id,
        "schema_id": schema_id,
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "credential_values": CREDENTIAL_VALUES,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(output, indent=2))
    log(f"Bootstrap output written to: {OUTPUT_FILE}")
    log(f"cred_def_id: {cred_def_id}")

    # Print cred_def_id as last line so CI can capture it
    print(cred_def_id)


if __name__ == "__main__":
    main()
