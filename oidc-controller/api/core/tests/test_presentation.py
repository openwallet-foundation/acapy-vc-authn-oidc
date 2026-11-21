from api.core.acapy.presentation import ByFormat

REQUEST = {"requested_attributes": {"r0": {"names": ["name"]}}}
PRES = {
    "requested_proof": {
        "revealed_attr_groups": {"r0": {"values": {"name": {"raw": "Alice"}}}}
    },
    "identifiers": [{"schema_id": "did:2:Person:1.0"}],
}


def test_select_uses_preferred_format():
    by_format = ByFormat.model_validate(
        {
            "pres_request": {"indy": REQUEST, "anoncreds": REQUEST},
            "pres": {"indy": PRES, "anoncreds": PRES},
        }
    )
    selected = by_format.select("anoncreds")
    assert selected is not None
    assert selected[0] == "anoncreds"


def test_select_falls_back_when_preferred_is_missing():
    by_format = ByFormat.model_validate(
        {"pres_request": {"indy": REQUEST}, "pres": {"indy": PRES}}
    )
    selected = by_format.select("anoncreds")
    assert selected is not None
    assert selected[0] == "indy"


def test_select_needs_both_request_and_presentation():
    by_format = ByFormat.model_validate(
        {"pres_request": {"indy": REQUEST}, "pres": {"anoncreds": PRES}}
    )
    assert by_format.select("indy") is None


def test_other_formats_are_ignored():
    by_format = ByFormat.model_validate(
        {
            "pres_request": {"dif": {"anything": 1}},
            "pres": {"dif": ["not", "a", "dict"]},
            "pres_proposal": {},
        }
    )
    assert by_format.select("indy") is None
    assert by_format.presentations() == []
