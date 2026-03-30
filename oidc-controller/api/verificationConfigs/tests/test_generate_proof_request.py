import time
from datetime import datetime
from unittest.mock import patch

import pytest

from api.core.config import settings
from api.verificationConfigs.helpers import VariableSubstitutionError
from api.verificationConfigs.models import (
    AttributeFilter,
    ReqAttr,
    ReqPred,
    VerificationConfig,
    VerificationProofRequest,
)


def _make_config(attrs=None, preds=None, name="test_proof_request"):
    return VerificationConfig(
        ver_config_id="test_id",
        subject_identifier="sub",
        proof_request=VerificationProofRequest(
            name=name,
            version="0.0.1",
            requested_attributes=attrs or [],
            requested_predicates=preds or [],
        ),
    )


class TestNonRevoked:
    def test_non_revoked_injected_when_enabled(self):
        config = _make_config(
            attrs=[ReqAttr(names=["given_name"], label="given", restrictions=[])],
            preds=[
                ReqPred(
                    name="age", label="age", restrictions=[], p_value=18, p_type=">="
                )
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", True):
            result = config.generate_proof_request()

        now = int(time.time())
        attr_nr = result["requested_attributes"]["given"]["non_revoked"]
        pred_nr = result["requested_predicates"]["age"]["non_revoked"]

        for nr in (attr_nr, pred_nr):
            assert "from" in nr
            assert "to" in nr
            assert abs(nr["from"] - now) < 2
            assert abs(nr["to"] - now) < 2
            assert nr["from"] <= nr["to"]

    def test_non_revoked_absent_when_disabled(self):
        config = _make_config(
            attrs=[ReqAttr(names=["given_name"], label="given", restrictions=[])],
            preds=[
                ReqPred(
                    name="age", label="age", restrictions=[], p_value=18, p_type=">="
                )
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", False):
            result = config.generate_proof_request()

        assert "non_revoked" not in result["requested_attributes"]["given"]
        assert "non_revoked" not in result["requested_predicates"]["age"]

    def test_non_revoked_injected_for_all_attributes(self):
        config = _make_config(
            attrs=[
                ReqAttr(names=["first_name"], label="first", restrictions=[]),
                ReqAttr(names=["last_name"], label="last", restrictions=[]),
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", True):
            result = config.generate_proof_request()

        assert "non_revoked" in result["requested_attributes"]["first"]
        assert "non_revoked" in result["requested_attributes"]["last"]


class TestVariableSubstitution:
    def test_threshold_years_as_pred_p_value(self):
        config = _make_config(
            preds=[
                ReqPred(
                    name="birthdate_dateint",
                    label="age_check",
                    restrictions=[],
                    p_value="$threshold_years_5",
                    p_type=">=",
                )
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", False):
            result = config.generate_proof_request()

        val = result["requested_predicates"]["age_check"]["p_value"]
        assert isinstance(val, int)
        assert 19000101 < val < 99991231

    def test_today_int_in_restriction(self):
        config = _make_config(
            attrs=[
                ReqAttr(
                    names=["schema_version"],
                    label="sv_check",
                    restrictions=[AttributeFilter(schema_version="$today_int")],
                )
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", False):
            result = config.generate_proof_request()

        expected = int(datetime.today().strftime("%Y%m%d"))
        val = result["requested_attributes"]["sv_check"]["restrictions"][0][
            "schema_version"
        ]
        assert val == expected

    def test_unknown_variable_raises(self):
        config = _make_config(
            attrs=[
                ReqAttr(
                    names=["cred_def_id"],
                    label="bad_var",
                    restrictions=[AttributeFilter(cred_def_id="$undefined")],
                )
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", False):
            with pytest.raises(VariableSubstitutionError):
                config.generate_proof_request()

    def test_no_variables_unaffected(self):
        config = _make_config(
            attrs=[
                ReqAttr(
                    names=["first_name", "last_name"],
                    label="name_label",
                    restrictions=[
                        AttributeFilter(schema_id="schema_1"),
                        AttributeFilter(cred_def_id="cred_def_1"),
                    ],
                )
            ],
            preds=[
                ReqPred(
                    name="age",
                    label="age_label",
                    restrictions=[AttributeFilter(schema_id="schema_2")],
                    p_value=18,
                    p_type=">=",
                )
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", False):
            result = config.generate_proof_request()

        attr = result["requested_attributes"]["name_label"]
        assert attr["names"] == ["first_name", "last_name"]
        assert attr["restrictions"][0]["schema_id"] == "schema_1"
        assert attr["restrictions"][1]["cred_def_id"] == "cred_def_1"

        pred = result["requested_predicates"]["age_label"]
        assert pred["p_value"] == 18
        assert pred["p_type"] == ">="


class TestAutoGeneratedLabels:
    def test_single_unlabeled_attr_and_pred(self):
        config = _make_config(
            attrs=[ReqAttr(names=["given_name"], label=None, restrictions=[])],
            preds=[
                ReqPred(
                    name="age", label=None, restrictions=[], p_value=18, p_type=">="
                )
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", False):
            result = config.generate_proof_request()

        assert "req_attr_0" in result["requested_attributes"]
        assert "req_pred_0" in result["requested_predicates"]

    def test_multiple_unlabeled_attrs_sequential(self):
        config = _make_config(
            attrs=[
                ReqAttr(names=["a"], label=None, restrictions=[]),
                ReqAttr(names=["b"], label=None, restrictions=[]),
                ReqAttr(names=["c"], label=None, restrictions=[]),
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", False):
            result = config.generate_proof_request()

        keys = set(result["requested_attributes"].keys())
        assert keys == {"req_attr_0", "req_attr_1", "req_attr_2"}
        assert result["requested_attributes"]["req_attr_0"]["names"] == ["a"]
        assert result["requested_attributes"]["req_attr_1"]["names"] == ["b"]
        assert result["requested_attributes"]["req_attr_2"]["names"] == ["c"]

    def test_mixed_explicit_and_implicit_uses_global_index(self):
        config = _make_config(
            attrs=[
                ReqAttr(names=["a"], label=None, restrictions=[]),
                ReqAttr(names=["b"], label="explicit_label", restrictions=[]),
                ReqAttr(names=["c"], label=None, restrictions=[]),
            ],
        )
        with patch.object(settings, "SET_NON_REVOKED", False):
            result = config.generate_proof_request()

        keys = set(result["requested_attributes"].keys())
        assert keys == {"req_attr_0", "explicit_label", "req_attr_2"}
        assert "req_attr_1" not in result["requested_attributes"]

    def test_explicit_label_takes_precedence(self):
        config = _make_config(
            attrs=[ReqAttr(names=["given_name"], label="my_label", restrictions=[])],
        )
        with patch.object(settings, "SET_NON_REVOKED", False):
            result = config.generate_proof_request()

        assert "my_label" in result["requested_attributes"]
        assert "req_attr_0" not in result["requested_attributes"]
