"""E2E tests: subject identifier strategies (docs/README.md §Subject Identifier Mapping).

Three documented options:

  Option 1 — subject_identifier matches a proof attribute
              → sub = raw_value@pres_req_conf_id
              (covered by all happy-path tests via e2e_ver_config_id)

  Option 2 — subject_identifier does not match, generate_consistent_identifier=False
              → sub = pyop UUID, different every session (ephemeral / no correlation)

  Option 3 — subject_identifier does not match, generate_consistent_identifier=True
              → sub = SHA256(canonical_proof_claims + @pres_req_conf_id), deterministic

Options 2 and 3 are tested here. Both use subject_identifier="" (empty string),
matching the canonical README example.

See: oidc-controller/api/core/oidc/issue_token_service.py  Token.get_claims()
     docs/README.md §Subject Identifier Mapping
"""

import asyncio
import re

import jwt
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.oob, pytest.mark.connection]


async def _run_flow(oidc_client, holder_admin, sse_client, ver_config_id) -> dict:
    """Run the full OOB flow and return the decoded id_token payload."""
    pid, invitation = await oidc_client.authorize(pres_req_conf_id=ver_config_id)
    sse_task = asyncio.create_task(
        sse_client.wait_for_status(pid, expected="verified", timeout=60)
    )
    await asyncio.sleep(0.5)
    await holder_admin.receive_invitation(invitation)
    await sse_task
    auth_code = await oidc_client.get_auth_code(pid)
    tokens = await oidc_client.get_token(auth_code)
    return jwt.decode(
        tokens["id_token"],
        options={"verify_signature": False},
        algorithms=["RS256"],
    )


@pytest.mark.asyncio
async def test_consistent_identifier_is_sha256_hash(
    oidc_client,
    holder_admin,
    sse_client,
    e2e_consistent_ver_config_id,
    holder_credential_values,
):
    """sub must be a 64-char hex SHA256 digest, not the raw attribute value."""
    claims = await _run_flow(
        oidc_client, holder_admin, sse_client, e2e_consistent_ver_config_id
    )
    sub = claims["sub"]

    assert re.fullmatch(r"[0-9a-f]{64}", sub), (
        f"sub is not a SHA256 hex digest: {sub!r}"
    )
    assert sub != holder_credential_values["first_name"], (
        "sub must be the hashed identifier, not the raw first_name value"
    )


@pytest.mark.asyncio
async def test_consistent_identifier_is_deterministic(
    oidc_client,
    holder_admin,
    sse_client,
    e2e_consistent_ver_config_id,
):
    """Two presentations of the same credential must produce the same sub."""
    claims1 = await _run_flow(
        oidc_client, holder_admin, sse_client, e2e_consistent_ver_config_id
    )
    claims2 = await _run_flow(
        oidc_client, holder_admin, sse_client, e2e_consistent_ver_config_id
    )

    assert claims1["sub"] == claims2["sub"], (
        f"Consistent identifier must be stable across sessions: "
        f"{claims1['sub']!r} != {claims2['sub']!r}"
    )


@pytest.mark.asyncio
async def test_consistent_identifier_differs_from_direct_identifier(
    oidc_client,
    holder_admin,
    sse_client,
    ver_config_id,
    e2e_consistent_ver_config_id,
):
    """The hashed sub must differ from the plain sub produced by the standard config."""
    plain_claims = await _run_flow(oidc_client, holder_admin, sse_client, ver_config_id)
    hashed_claims = await _run_flow(
        oidc_client, holder_admin, sse_client, e2e_consistent_ver_config_id
    )

    assert plain_claims["sub"] != hashed_claims["sub"], (
        "Consistent identifier config must produce a different sub than the "
        "direct-attribute config"
    )


# ---------------------------------------------------------------------------
# Option 2: ephemeral identifier (generate_consistent_identifier=False,
#           subject_identifier does not match any proof attribute)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ephemeral_identifier_is_present(
    oidc_client,
    holder_admin,
    sse_client,
    e2e_ephemeral_ver_config_id,
    holder_credential_values,
):
    """sub must be present and must not be the raw credential attribute value.

    When no subject_identifier matches and generate_consistent_identifier=False,
    pyop hashes a fresh UUID via HashBasedSubjectIdentifierFactory. The result
    is still a 64-char hex string — the difference from Option 3 is determinism,
    not format. The determinism test below is what distinguishes the two options.
    """
    claims = await _run_flow(
        oidc_client, holder_admin, sse_client, e2e_ephemeral_ver_config_id
    )
    sub = claims.get("sub", "")

    assert sub, "id_token must contain a non-empty sub"
    assert sub != holder_credential_values["first_name"], (
        "sub must not be the raw first_name value"
    )


@pytest.mark.asyncio
async def test_ephemeral_identifier_differs_per_session(
    oidc_client,
    holder_admin,
    sse_client,
    e2e_ephemeral_ver_config_id,
):
    """Each session must produce a different sub (no cross-session correlation).

    This is the core documented property of Option 2: the ephemeral identifier
    prevents an IAM solution from correlating the same user across logins.
    """
    claims1 = await _run_flow(
        oidc_client, holder_admin, sse_client, e2e_ephemeral_ver_config_id
    )
    claims2 = await _run_flow(
        oidc_client, holder_admin, sse_client, e2e_ephemeral_ver_config_id
    )

    assert claims1["sub"] != claims2["sub"], (
        f"Ephemeral identifier must differ per session: "
        f"{claims1['sub']!r} == {claims2['sub']!r}"
    )
