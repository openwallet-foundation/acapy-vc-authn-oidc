"""Bodies of the ACA-Py webhooks the controller handles.

Fields not listed here are ignored. ACA-Py may add states over time, so state
and role stay plain strings rather than enums.
"""

from typing import Any, Literal

from ..models import FrozenModel


class ConnectionWebhook(FrozenModel):
    connection_id: str | None = None
    state: str | None = None
    invitation_msg_id: str | None = None
    invi_msg_id: str | None = None
    invitation_id: str | None = None

    def invitation_search_id(self) -> str | None:
        return self.invitation_msg_id or self.invi_msg_id or self.invitation_id


class PresentProofWebhook(FrozenModel):
    pres_ex_id: str
    state: str | None = None
    role: str | None = None
    connection_id: str | None = None
    # ACA-Py sends "true" or "false" as strings.
    verified: Literal["true", "false"] | None = None
    error_msg: str | None = None
    # Stored on the session as sent, so it stays a plain dict here.
    by_format: dict[str, Any] | None = None

    @property
    def is_verified(self) -> bool:
        return self.verified == "true"
