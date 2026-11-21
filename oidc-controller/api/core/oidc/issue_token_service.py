import dataclasses
import hashlib
import json
from typing import Any

import canonicaljson
import structlog
from pydantic import ValidationError

from ...authSessions.models import AuthSession
from ...core.models import FrozenModel
from ...verificationConfigs.models import VerificationConfig
from ..acapy.presentation import ByFormat

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

PROOF_CLAIMS_ATTRIBUTE_NAME = "vc_presented_attributes"


@dataclasses.dataclass(frozen=True)
class Claim(FrozenModel):
    type: str
    value: str


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
        proof_format: str,
    ) -> dict[str, str]:
        """Converts vc presentation values to oidc claims"""
        oidc_claims: list[Claim] = [
            Claim(
                type="pres_req_conf_id",
                value=auth_session.request_parameters["pres_req_conf_id"],
            ),
            Claim(type="acr", value="vc_authn"),
        ]
        # subject claim

        # Conditionally append nonce as it is optional in Auth Code flow
        if "nonce" in auth_session.request_parameters:
            oidc_claims.append(
                Claim(type="nonce", value=auth_session.request_parameters["nonce"])
            )

        presentation_claims: dict[str, Claim] = {}

        try:
            by_format = ByFormat.model_validate(
                auth_session.presentation_exchange or {}
            )
        except ValidationError as err:
            logger.error(
                f"Presentation exchange does not match the expected shape: {err}"
            )
            raise RuntimeError(err) from err

        # Falls back to another format when the record has no data for the
        # configured one, e.g. for sessions in flight during a config change.
        selected = by_format.select(proof_format)
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
            for referent, requested_attr in pres_request.requested_attributes.items():
                logger.debug(
                    f"Processing referent: {referent}, requested_attr: {requested_attr}"
                )
                # loop through each value and put it in token as a claim
                for attr_name in requested_attr.names:
                    logger.debug(f"AttrName: {attr_name}")
                    presentation_claims[attr_name] = Claim(
                        type=attr_name,
                        value=revealed_attrs[referent].values[attr_name].raw,
                    )
                    logger.debug(f"Compiled presentation_claims: {presentation_claims}")
        except Exception as err:
            logger.error(
                f"An exception occurred while extracting the proof claims: {err}"
            )
            raise RuntimeError(err) from err

        proof_claims = json.dumps(
            {c.type: c.value for c in presentation_claims.values()}
        )
        # look at all presentation_claims for one
        # matching the configured subject_identifier, if any
        sub_id_claim = presentation_claims.get(ver_config.subject_identifier)

        pres_req_conf_id_suffix = (
            f"@{auth_session.request_parameters['pres_req_conf_id']}"
        )

        if sub_id_claim:
            # add sub and append presentation_claims
            oidc_claims.append(
                Claim(
                    type="sub",
                    value=sub_id_claim.value + pres_req_conf_id_suffix,
                )
            )

        elif ver_config.generate_consistent_identifier:
            # Do not create a sub based on the proof claims if the
            # user requests a generated identifier
            # Generate a SHA256 hash of the canonicaljson encoded proof_claims
            encoded_json: bytes = canonicaljson.encode_canonical_json(proof_claims)
            sha256_hash = hashlib.sha256(
                encoded_json + pres_req_conf_id_suffix.encode()
            ).hexdigest()
            oidc_claims.append(
                Claim(
                    type="sub",
                    value=sha256_hash,
                )
            )

        result = {c.type: c.value for c in oidc_claims}
        result[PROOF_CLAIMS_ATTRIBUTE_NAME] = proof_claims

        # TODO: Remove after full transistion to v2.0
        # Add the presentation claims to the result as keys
        # for backwards compatibility [v1.0]
        if ver_config.include_v1_attributes:
            for key, value in presentation_claims.items():
                result[key] = value.value

        return result
