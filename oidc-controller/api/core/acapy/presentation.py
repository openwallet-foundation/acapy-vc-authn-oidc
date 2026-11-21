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


class Presentations(FrozenModel):
    indy: Presentation | None = None
    anoncreds: Presentation | None = None


class ByFormat(FrozenModel):
    pres_request: PresentationRequests = Field(default_factory=PresentationRequests)
    pres: Presentations = Field(default_factory=Presentations)

    def presentations(self) -> list[Presentation]:
        return [p for p in (self.pres.indy, self.pres.anoncreds) if p]

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
