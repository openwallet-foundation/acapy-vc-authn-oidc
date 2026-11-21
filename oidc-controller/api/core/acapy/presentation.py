"""Typed view of the by_format field of an ACA-Py presentation exchange.

Only the indy and anoncreds formats are read. Other formats and any fields not
listed here are ignored, and the stored record is left as ACA-Py sent it.
"""

from pydantic import Field

from ..models import FrozenModel


class RequestedAttribute(FrozenModel):
    names: list[str]


class PresentationRequest(FrozenModel):
    requested_attributes: dict[str, RequestedAttribute]


class RevealedValue(FrozenModel):
    raw: str


class RevealedAttrGroup(FrozenModel):
    values: dict[str, RevealedValue]


class RequestedProof(FrozenModel):
    revealed_attr_groups: dict[str, RevealedAttrGroup] = Field(default_factory=dict)


class Identifier(FrozenModel):
    schema_id: str | None = None
    cred_def_id: str | None = None


class Presentation(FrozenModel):
    requested_proof: RequestedProof = Field(default_factory=RequestedProof)
    identifiers: list[Identifier] = Field(default_factory=list)


class PresentationRequests(FrozenModel):
    indy: PresentationRequest | None = None
    anoncreds: PresentationRequest | None = None


def _schema_name(schema_id: str) -> str:
    # schema_id is <issuer_did>:2:<schema_name>:<version>. The issuer DID may
    # contain colons itself (did:sov:ABC), so split on the ":2:" marker.
    _, marker, remainder = schema_id.partition(":2:")
    return remainder.split(":")[0] if marker else schema_id


def _issuer_did(cred_def_id: str) -> str:
    # cred_def_id is <issuer_did>:3:CL:<schema_seq_no>:<tag>.
    issuer, marker, _ = cred_def_id.partition(":3:CL:")
    return issuer if marker else cred_def_id


class Presentations(FrozenModel):
    indy: Presentation | None = None
    anoncreds: Presentation | None = None

    def identifiers(self) -> list[Identifier]:
        return [
            identifier
            for presentation in (self.indy, self.anoncreds)
            if presentation is not None
            for identifier in presentation.identifiers
        ]

    def schema_names(self) -> list[str]:
        return sorted(
            {_schema_name(i.schema_id) for i in self.identifiers() if i.schema_id}
        )

    def issuer_dids(self) -> list[str]:
        return sorted(
            {_issuer_did(i.cred_def_id) for i in self.identifiers() if i.cred_def_id}
        )


class ByFormat(FrozenModel):
    pres_request: PresentationRequests = Field(default_factory=PresentationRequests)
    pres: Presentations = Field(default_factory=Presentations)

    def select(
        self, preferred: str
    ) -> tuple[str, PresentationRequest, Presentation] | None:
        """Return the request and presentation for the preferred format.

        Falls back to indy, then anoncreds, when the record has no data for the
        preferred format, for example when the setting changed mid-session.
        """
        for proof_format in (preferred, "indy", "anoncreds"):
            match proof_format:
                case "indy":
                    pair = (self.pres_request.indy, self.pres.indy)
                case "anoncreds":
                    pair = (self.pres_request.anoncreds, self.pres.anoncreds)
                case _:
                    continue
            request, presentation = pair
            if request is not None and presentation is not None:
                return proof_format, request, presentation
        return None
