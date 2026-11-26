import hashlib
import json
from typing import Any, Literal

import canonicaljson
import structlog
from pydantic import ValidationError

from ...authSessions.models import AuthSession
from ...core.models import FrozenModel
from ...verificationConfigs.models import VerificationConfig
from ..acapy.presentation import ProofFormat, select_format

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

PROOF_CLAIMS_ATTRIBUTE_NAME = "vc_presented_attributes"


class Claims(FrozenModel):
    """OIDC claims for a verified presentation."""

    pres_req_conf_id: str
    acr: Literal["vc_authn"] = "vc_authn"
    # Only in the Standard/Implicit flows; optional in the Auth Code flow.
    nonce: str | None
    # The presentation's subject, or None to keep the sub PyOP generated.
    sub: str | None
    # JSON object of the presented attribute values.
    vc_presented_attributes: str
    # The presented attributes again as top-level claims, for v1 clients.
    # Empty unless the verification config sets include_v1_attributes.
    # TODO: Remove after full transistion to v2.0
    v1_attributes: dict[str, str]

    def for_pyop(self) -> dict[str, str]:
        """The claims for PyOP's userinfo, without sub.

        PyOP reads sub from authz_info; passing it in the claims as well makes
        IdToken() receive it twice and raise a TypeError. v1 attributes come
        last, so they win over the standard claims they share a name with.
        """
        return {
            "pres_req_conf_id": self.pres_req_conf_id,
            "acr": self.acr,
            **({"nonce": self.nonce} if self.nonce is not None else {}),
            PROOF_CLAIMS_ATTRIBUTE_NAME: self.vc_presented_attributes,
            **{k: v for k, v in self.v1_attributes.items() if k != "sub"},
        }


class Token(FrozenModel):
    issuer: str
    audiences: list[str]
    lifetime: int
    claims: dict[str, Any]

    @classmethod
    def get_claims(
        cls,
        auth_session: AuthSession,
        ver_config: VerificationConfig,
        proof_format: ProofFormat,
    ) -> Claims:
        """Converts vc presentation values to oidc claims"""
        params = auth_session.request_parameters
        pres_req_conf_id = params["pres_req_conf_id"]

        # Falls back to another format when the record has no data for the
        # configured one, e.g. for sessions in flight during a config change.
        try:
            selected = select_format(
                auth_session.presentation_exchange or {}, proof_format
            )
        except ValidationError as err:
            # The error count only: the errors themselves can echo credential values.
            logger.error(
                "Presentation exchange does not match the expected shape",
                error_count=err.error_count(),
            )
            raise RuntimeError(
                "Presentation exchange does not match the expected shape"
            ) from None
        if selected is None:
            raise ValueError("No valid proof format found in presentation exchange")
        selected_format, pres_request, presentation = selected
        if selected_format != proof_format:
            logger.debug(
                f"Configured proof format '{proof_format}' not found in record, falling back to '{selected_format}'"
            )

        logger.info(
            "Extracted requested attributes from presentation request",
            requested_attributes={
                referent: attr.names
                for referent, attr in pres_request.requested_attributes.items()
            },
            proof_format=selected_format,
        )

        revealed_attrs = presentation.requested_proof.revealed_attr_groups
        try:
            presentation_claims = {
                attr_name: revealed_attrs[referent].values[attr_name].raw
                for referent, requested_attr in pres_request.requested_attributes.items()
                for attr_name in requested_attr.names
            }
        except Exception as err:
            logger.error(
                f"An exception occurred while extracting the proof claims: {err}"
            )
            raise RuntimeError(err) from err

        proof_claims = json.dumps(presentation_claims)
        v1_attributes = presentation_claims if ver_config.include_v1_attributes else {}
        # A v1 attribute named "sub" has always replaced the subject.
        sub = (
            v1_attributes["sub"]
            if "sub" in v1_attributes
            else _subject(
                presentation_claims, proof_claims, f"@{pres_req_conf_id}", ver_config
            )
        )
        return Claims(
            pres_req_conf_id=pres_req_conf_id,
            nonce=params.get("nonce"),
            sub=sub or None,
            vc_presented_attributes=proof_claims,
            v1_attributes=v1_attributes,
        )


def _subject(
    presentation_claims: dict[str, str],
    proof_claims: str,
    suffix: str,
    ver_config: VerificationConfig,
) -> str | None:
    """The sub claim: the configured subject attribute, else a hash if asked for."""
    if (value := presentation_claims.get(ver_config.subject_identifier)) is not None:
        return value + suffix
    if ver_config.generate_consistent_identifier:
        # SHA256 of the canonical JSON of the proof claims, so the same
        # credential values give the same sub.
        encoded_json: bytes = canonicaljson.encode_canonical_json(proof_claims)
        return hashlib.sha256(encoded_json + suffix.encode()).hexdigest()
    return None
