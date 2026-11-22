import pytest
from api.core.acapy.presentation import Presentations, select_format
from pydantic import ValidationError

REQUEST = {"requested_attributes": {"r0": {"names": ["name"]}}}
PRES = {
    "requested_proof": {
        "revealed_attr_groups": {"r0": {"values": {"name": {"raw": "Alice"}}}}
    },
    "identifiers": [{"schema_id": "did:2:Person:1.0"}],
}


def test_select_uses_preferred_format():
    by_format = {
        "pres_request": {"indy": REQUEST, "anoncreds": REQUEST},
        "pres": {"indy": PRES, "anoncreds": PRES},
    }
    selected = select_format(by_format, "anoncreds")
    assert selected is not None
    assert selected[0] == "anoncreds"


def test_select_falls_back_when_preferred_is_missing():
    by_format = {"pres_request": {"indy": REQUEST}, "pres": {"indy": PRES}}
    selected = select_format(by_format, "anoncreds")
    assert selected is not None
    assert selected[0] == "indy"


def test_select_needs_both_request_and_presentation():
    by_format = {"pres_request": {"indy": REQUEST}, "pres": {"anoncreds": PRES}}
    assert select_format(by_format, "indy") is None


def test_other_formats_are_ignored():
    by_format = {
        "pres_request": {"dif": {"anything": 1}},
        "pres": {"dif": ["not", "a", "dict"]},
        "pres_proposal": {},
    }
    assert select_format(by_format, "indy") is None
    assert Presentations.model_validate(by_format["pres"]).identifiers() == []


def test_select_ignores_a_malformed_unused_format():
    by_format = {
        "pres_request": {"indy": REQUEST, "anoncreds": "malformed"},
        "pres": {"indy": PRES, "anoncreds": "malformed"},
    }
    selected = select_format(by_format, "indy")
    assert selected is not None
    assert selected[0] == "indy"


def test_select_ignores_malformed_identifiers():
    pres = {**PRES, "identifiers": [{"schema_id": 42}]}
    by_format = {"pres_request": {"indy": REQUEST}, "pres": {"indy": pres}}
    selected = select_format(by_format, "indy")
    assert selected is not None
    revealed = selected[2].requested_proof.revealed_attr_groups
    assert revealed["r0"].values["name"].raw == "Alice"


def test_select_rejects_a_malformed_selected_format():
    by_format = {
        "pres_request": {"indy": {"requested_attributes": "malformed"}},
        "pres": {"indy": PRES},
    }
    with pytest.raises(ValidationError):
        select_format(by_format, "indy")


def test_reads_identifiers_from_both_formats():
    pres = Presentations.model_validate(
        {
            "indy": {"identifiers": [{"cred_def_id": "did:sov:B:3:CL:2:t"}]},
            "anoncreds": {
                "identifiers": [
                    {"schema_id": "did:sov:A:2:Person:1.0"},
                    {"cred_def_id": "did:sov:A:3:CL:1:t"},
                ]
            },
        }
    )
    assert pres.schema_names() == ["Person"]
    assert pres.issuer_dids() == ["did:sov:A", "did:sov:B"]
