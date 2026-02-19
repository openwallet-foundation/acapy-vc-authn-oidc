"""Tests for the SIAM Audit Logger module."""

import hashlib
import os
from unittest.mock import MagicMock, patch

import pytest
from api.verificationConfigs.models import (
    AttributeFilter,
    ReqAttr,
    ReqPred,
    VerificationConfig,
    VerificationProofRequest,
)

# ---------------------------------------------------------------------------
# Helpers – build mock VerificationConfig objects
# ---------------------------------------------------------------------------


def _make_ver_config(
    ver_config_id: str = "test-vc-config-1",
    schema_names: list[str] | None = None,
    issuer_dids: list[str] | None = None,
    schema_issuer_dids: list[str] | None = None,
    proof_name: str | None = "age-verification",
    num_predicates: int = 0,
    predicate_schema_names: list[str] | None = None,
    predicate_issuer_dids: list[str] | None = None,
    predicate_schema_issuer_dids: list[str] | None = None,
) -> VerificationConfig:
    """Build a lightweight VerificationConfig for testing."""
    restrictions = []
    if schema_names:
        for sn in schema_names:
            restrictions.append(
                AttributeFilter(
                    schema_name=sn,
                    issuer_did=(issuer_dids or [None])[0],
                    schema_issuer_did=(schema_issuer_dids or [None])[0],
                )
            )
    if not restrictions:
        restrictions = [AttributeFilter()]

    requested_attributes = [
        ReqAttr(names=["given_names"], restrictions=restrictions),
    ]

    # Build predicate restrictions
    pred_restrictions: list[AttributeFilter] = []
    if predicate_schema_names:
        for sn in predicate_schema_names:
            pred_restrictions.append(
                AttributeFilter(
                    schema_name=sn,
                    issuer_did=(predicate_issuer_dids or [None])[0],
                    schema_issuer_did=(predicate_schema_issuer_dids or [None])[0],
                )
            )

    requested_predicates = []
    for i in range(num_predicates):
        requested_predicates.append(
            ReqPred(
                name=f"pred_{i}",
                restrictions=pred_restrictions or [AttributeFilter()],
                p_value=19,
                p_type=">=",
            )
        )

    return VerificationConfig(
        ver_config_id=ver_config_id,
        subject_identifier="given_names",
        proof_request=VerificationProofRequest(
            name=proof_name,
            version="0.0.1",
            requested_attributes=requested_attributes,
            requested_predicates=requested_predicates,
        ),
    )


# ===================================================================
# _strtobool
# ===================================================================


class TestStrtobool:
    """Tests for the _strtobool helper."""

    def test_truthy_strings(self):
        from api.core.siam_audit import _strtobool

        for val in ("y", "yes", "t", "true", "on", "1", "YES", "True", "ON"):
            assert _strtobool(val) is True

    def test_falsy_strings(self):
        from api.core.siam_audit import _strtobool

        for val in ("n", "no", "f", "false", "off", "0", "NO", "False", "OFF"):
            assert _strtobool(val) is False

    def test_bool_passthrough(self):
        from api.core.siam_audit import _strtobool

        assert _strtobool(True) is True
        assert _strtobool(False) is False

    def test_invalid_value_raises(self):
        from api.core.siam_audit import _strtobool

        with pytest.raises(ValueError, match="invalid truth value"):
            _strtobool("maybe")


# ===================================================================
# _anonymize_ip
# ===================================================================


class TestAnonymizeIp:
    """Tests for IP anonymization."""

    def test_none_returns_none(self):
        from api.core.siam_audit import _anonymize_ip

        assert _anonymize_ip(None) is None

    def test_empty_string_returns_none(self):
        from api.core.siam_audit import _anonymize_ip

        assert _anonymize_ip("") is None

    def test_returns_16_char_hex(self):
        from api.core.siam_audit import _anonymize_ip

        result = _anonymize_ip("192.168.1.1")
        assert isinstance(result, str)
        assert len(result) == 16
        # Verify it's valid hex
        int(result, 16)

    def test_deterministic(self):
        from api.core.siam_audit import _anonymize_ip

        assert _anonymize_ip("10.0.0.1") == _anonymize_ip("10.0.0.1")

    def test_different_ips_differ(self):
        from api.core.siam_audit import _anonymize_ip

        assert _anonymize_ip("10.0.0.1") != _anonymize_ip("10.0.0.2")


# ===================================================================
# _extract_user_agent_family
# ===================================================================


class TestExtractUserAgentFamily:
    """Tests for User-Agent family extraction."""

    def test_none_returns_none(self):
        from api.core.siam_audit import _extract_user_agent_family

        assert _extract_user_agent_family(None) is None

    def test_empty_string_returns_none(self):
        from api.core.siam_audit import _extract_user_agent_family

        assert _extract_user_agent_family("") is None

    @pytest.mark.parametrize(
        "ua_string,expected",
        [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Chrome",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 "
                "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Safari",
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
                "Firefox",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                "Edge",
            ),
            # Modern Opera UAs contain "Chrome" so they match Chrome first
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/105.0.0.0",
                "Chrome",
            ),
            # Legacy Opera UA (no Chrome substring) hits the Opera branch
            (
                "Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18",
                "Opera",
            ),
            # MobileSafari contains "safari" so it matches Safari first
            ("MobileSafari/604.1", "Safari"),
            # Pure mobile UA without safari
            ("SomeMobileApp/1.0 (Linux; Android 13; Mobile)", "Mobile"),
            ("Googlebot/2.1 (+http://www.google.com/bot.html)", "Bot"),
            ("WebCrawler/1.0", "Bot"),
            ("some-unknown-client/1.0", "Other"),
        ],
    )
    def test_browser_families(self, ua_string, expected):
        from api.core.siam_audit import _extract_user_agent_family

        assert _extract_user_agent_family(ua_string) == expected


# ===================================================================
# _extract_schema_names / _extract_issuer_dids
# ===================================================================


class TestExtractSchemaNames:
    """Tests for schema name extraction from VerificationConfig."""

    def test_no_schema_names(self):
        from api.core.siam_audit import _extract_schema_names

        vc = _make_ver_config(schema_names=None)
        assert _extract_schema_names(vc) == []

    def test_single_schema(self):
        from api.core.siam_audit import _extract_schema_names

        vc = _make_ver_config(schema_names=["Person"])
        assert _extract_schema_names(vc) == ["Person"]

    def test_multiple_schemas_sorted_and_deduped(self):
        from api.core.siam_audit import _extract_schema_names

        # Two restrictions with same schema → should deduplicate
        vc = _make_ver_config(schema_names=["Zebra", "Alpha", "Alpha"])
        assert _extract_schema_names(vc) == ["Alpha", "Zebra"]

    def test_schemas_from_predicates(self):
        from api.core.siam_audit import _extract_schema_names

        vc = _make_ver_config(
            num_predicates=1,
            predicate_schema_names=["AgeCredential"],
        )
        result = _extract_schema_names(vc)
        assert "AgeCredential" in result

    def test_schemas_merged_from_attributes_and_predicates(self):
        from api.core.siam_audit import _extract_schema_names

        vc = _make_ver_config(
            schema_names=["Person"],
            num_predicates=1,
            predicate_schema_names=["AgeCredential"],
        )
        result = _extract_schema_names(vc)
        assert result == ["AgeCredential", "Person"]

    def test_schemas_deduped_across_attributes_and_predicates(self):
        from api.core.siam_audit import _extract_schema_names

        vc = _make_ver_config(
            schema_names=["Person"],
            num_predicates=1,
            predicate_schema_names=["Person"],
        )
        result = _extract_schema_names(vc)
        assert result == ["Person"]


class TestExtractIssuerDids:
    """Tests for issuer DID extraction from VerificationConfig."""

    def test_no_issuers(self):
        from api.core.siam_audit import _extract_issuer_dids

        vc = _make_ver_config()
        assert _extract_issuer_dids(vc) == []

    def test_issuer_did_extracted(self):
        from api.core.siam_audit import _extract_issuer_dids

        vc = _make_ver_config(
            schema_names=["Person"],
            issuer_dids=["did:sov:abc123"],
        )
        result = _extract_issuer_dids(vc)
        assert "did:sov:abc123" in result

    def test_schema_issuer_did_extracted(self):
        from api.core.siam_audit import _extract_issuer_dids

        vc = _make_ver_config(
            schema_names=["Person"],
            schema_issuer_dids=["did:sov:xyz789"],
        )
        result = _extract_issuer_dids(vc)
        assert "did:sov:xyz789" in result

    def test_issuer_dids_from_predicates(self):
        from api.core.siam_audit import _extract_issuer_dids

        vc = _make_ver_config(
            num_predicates=1,
            predicate_schema_names=["AgeCredential"],
            predicate_issuer_dids=["did:sov:pred1"],
        )
        result = _extract_issuer_dids(vc)
        assert "did:sov:pred1" in result

    def test_schema_issuer_dids_from_predicates(self):
        from api.core.siam_audit import _extract_issuer_dids

        vc = _make_ver_config(
            num_predicates=1,
            predicate_schema_names=["AgeCredential"],
            predicate_schema_issuer_dids=["did:sov:spred1"],
        )
        result = _extract_issuer_dids(vc)
        assert "did:sov:spred1" in result

    def test_issuer_dids_merged_from_attributes_and_predicates(self):
        from api.core.siam_audit import _extract_issuer_dids

        vc = _make_ver_config(
            schema_names=["Person"],
            issuer_dids=["did:sov:attr1"],
            num_predicates=1,
            predicate_schema_names=["AgeCredential"],
            predicate_issuer_dids=["did:sov:pred1"],
        )
        result = _extract_issuer_dids(vc)
        assert result == ["did:sov:attr1", "did:sov:pred1"]

    def test_issuer_dids_deduped_across_attributes_and_predicates(self):
        from api.core.siam_audit import _extract_issuer_dids

        vc = _make_ver_config(
            schema_names=["Person"],
            issuer_dids=["did:sov:shared"],
            num_predicates=1,
            predicate_schema_names=["AgeCredential"],
            predicate_issuer_dids=["did:sov:shared"],
        )
        result = _extract_issuer_dids(vc)
        assert result == ["did:sov:shared"]

    def test_both_dids_deduplicated_and_sorted(self):
        from api.core.siam_audit import _extract_issuer_dids

        vc = _make_ver_config(
            schema_names=["Person"],
            issuer_dids=["did:sov:z"],
            schema_issuer_dids=["did:sov:a"],
        )
        result = _extract_issuer_dids(vc)
        assert result == ["did:sov:a", "did:sov:z"]


# ===================================================================
# audit_event – core dispatcher
# ===================================================================


class TestAuditEvent:
    """Tests for the central audit_event function."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_basic_event_logged(self, mock_logger):
        from api.core.siam_audit import audit_event

        audit_event("webhook_received", session_id="sess-1")

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "audit_webhook_received"
        assert call_args[1]["session_id"] == "sess-1"
        assert call_args[1]["audit_event_type"] == "webhook_received"
        assert call_args[1]["service"] == "vc-authn-oidc"
        assert "timestamp" in call_args[1]

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", False)
    def test_disabled_flag_suppresses_logging(self, mock_logger):
        from api.core.siam_audit import audit_event

        audit_event("webhook_received", session_id="sess-1")
        mock_logger.info.assert_not_called()

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_none_fields_omitted(self, mock_logger):
        from api.core.siam_audit import audit_event

        audit_event("webhook_received")

        call_kwargs = mock_logger.info.call_args[1]
        assert "session_id" not in call_kwargs
        assert "client_id" not in call_kwargs
        assert "outcome" not in call_kwargs
        assert "client_ip_hash" not in call_kwargs

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_ip_anonymized_in_output(self, mock_logger):
        from api.core.siam_audit import audit_event

        audit_event("qr_scanned", client_ip="1.2.3.4")

        call_kwargs = mock_logger.info.call_args[1]
        assert "client_ip_hash" in call_kwargs
        # Raw IP must NOT be in the log data
        assert "1.2.3.4" not in str(call_kwargs)

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_user_agent_reduced_to_family(self, mock_logger):
        from api.core.siam_audit import audit_event

        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        audit_event("qr_scanned", user_agent=ua)

        call_kwargs = mock_logger.info.call_args[1]
        assert call_kwargs["user_agent_family"] == "Chrome"
        # Full UA must NOT be in the log data
        assert "Mozilla" not in str(call_kwargs)

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_extra_safe_fields_included(self, mock_logger):
        from api.core.siam_audit import audit_event

        audit_event(
            "webhook_received",
            webhook_topic="present_proof_v2_0",
            webhook_state="done",
        )

        call_kwargs = mock_logger.info.call_args[1]
        assert call_kwargs["webhook_topic"] == "present_proof_v2_0"
        assert call_kwargs["webhook_state"] == "done"

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_outcome_and_failure_category(self, mock_logger):
        from api.core.siam_audit import audit_event

        audit_event(
            "proof_verification_failed",
            outcome="failed",
            failure_category="revoked",
        )

        call_kwargs = mock_logger.info.call_args[1]
        assert call_kwargs["outcome"] == "failed"
        assert call_kwargs["failure_category"] == "revoked"


# ===================================================================
# High-level convenience functions
# ===================================================================


class TestAuditAuthSessionInitiated:
    """Tests for audit_auth_session_initiated."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_logs_session_metadata(self, mock_logger):
        from api.core.siam_audit import audit_auth_session_initiated

        vc = _make_ver_config(
            schema_names=["Person"],
            issuer_dids=["did:sov:abc"],
            num_predicates=2,
        )
        audit_auth_session_initiated(
            session_id="sess-42",
            client_id="keycloak-1",
            ver_config=vc,
            client_ip="10.0.0.5",
            user_agent="Chrome/120",
        )

        mock_logger.info.assert_called_once()
        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "auth_session_initiated"
        assert kw["session_id"] == "sess-42"
        assert kw["client_id"] == "keycloak-1"
        assert kw["ver_config_id"] == "test-vc-config-1"
        assert kw["requested_schemas"] == ["Person"]
        assert kw["requested_attributes_count"] == 1
        assert kw["requested_predicates_count"] == 2
        assert "client_ip_hash" in kw
        assert kw["user_agent_family"] == "Chrome"


class TestAuditProofRequestCreated:
    """Tests for audit_proof_request_created."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_logs_proof_request(self, mock_logger):
        from api.core.siam_audit import audit_proof_request_created

        vc = _make_ver_config(
            schema_names=["Licence"],
            issuer_dids=["did:sov:gov"],
        )
        audit_proof_request_created(session_id="sess-1", ver_config=vc)

        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "proof_request_created"
        assert kw["proof_name"] == "age-verification"
        assert kw["requested_schemas"] == ["Licence"]
        assert "did:sov:gov" in kw["expected_issuers"]

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_custom_proof_name_overrides(self, mock_logger):
        from api.core.siam_audit import audit_proof_request_created

        vc = _make_ver_config()
        audit_proof_request_created(
            session_id="sess-1",
            ver_config=vc,
            proof_name="custom-proof",
        )

        kw = mock_logger.info.call_args[1]
        assert kw["proof_name"] == "custom-proof"


class TestAuditQrScanned:
    """Tests for audit_qr_scanned."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_qr_code_scan(self, mock_logger):
        from api.core.siam_audit import audit_qr_scanned

        audit_qr_scanned(
            session_id="sess-1",
            scan_method="qr_code",
            client_ip="1.1.1.1",
            user_agent="Safari/17",
        )

        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "qr_scanned"
        assert kw["scan_method"] == "qr_code"
        assert kw["user_agent_family"] == "Safari"

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_deep_link_scan(self, mock_logger):
        from api.core.siam_audit import audit_qr_scanned

        audit_qr_scanned(session_id="sess-2", scan_method="deep_link")

        kw = mock_logger.info.call_args[1]
        assert kw["scan_method"] == "deep_link"


class TestAuditProofVerified:
    """Tests for audit_proof_verified."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_logs_verification_metadata(self, mock_logger):
        from api.core.siam_audit import audit_proof_verified

        audit_proof_verified(
            session_id="sess-1",
            ver_config_id="vc-1",
            credential_schemas=["Person", "Licence"],
            issuer_dids=["did:sov:abc"],
            duration_ms=450,
            revocation_checked=True,
        )

        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "proof_verified"
        assert kw["outcome"] == "verified"
        assert kw["credential_schemas"] == ["Person", "Licence"]
        assert kw["credential_count"] == 2
        assert kw["revocation_checked"] is True
        assert kw["duration_ms"] == 450


class TestAuditProofVerificationFailed:
    """Tests for audit_proof_verification_failed."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_logs_failure(self, mock_logger):
        from api.core.siam_audit import audit_proof_verification_failed

        audit_proof_verification_failed(
            session_id="sess-1",
            ver_config_id="vc-1",
            failure_category="revoked",
            duration_ms=120,
        )

        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "proof_verification_failed"
        assert kw["outcome"] == "failed"
        assert kw["failure_category"] == "revoked"

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_default_failure_category(self, mock_logger):
        from api.core.siam_audit import audit_proof_verification_failed

        audit_proof_verification_failed(
            session_id="sess-1",
            ver_config_id="vc-1",
        )

        kw = mock_logger.info.call_args[1]
        assert kw["failure_category"] == "unknown"


class TestAuditSessionAbandoned:
    """Tests for audit_session_abandoned."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_logs_abandonment(self, mock_logger):
        from api.core.siam_audit import audit_session_abandoned

        audit_session_abandoned(
            session_id="sess-1",
            ver_config_id="vc-1",
            phase="qr_scan",
            duration_ms=5000,
        )

        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "session_abandoned"
        assert kw["outcome"] == "abandoned"
        assert kw["phase"] == "qr_scan"

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_default_phase(self, mock_logger):
        from api.core.siam_audit import audit_session_abandoned

        audit_session_abandoned(session_id="sess-1", ver_config_id="vc-1")

        kw = mock_logger.info.call_args[1]
        assert kw["phase"] == "wallet_response"


class TestAuditSessionExpired:
    """Tests for audit_session_expired."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_logs_expiry(self, mock_logger):
        from api.core.siam_audit import audit_session_expired

        audit_session_expired(
            session_id="sess-1",
            ver_config_id="vc-1",
            phase="wallet_response",
            timeout_seconds=300,
        )

        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "session_expired"
        assert kw["outcome"] == "expired"
        assert kw["timeout_seconds"] == 300

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_default_phase(self, mock_logger):
        from api.core.siam_audit import audit_session_expired

        audit_session_expired(session_id="sess-1", ver_config_id="vc-1")

        kw = mock_logger.info.call_args[1]
        assert kw["phase"] == "qr_scan"


class TestAuditTokenIssued:
    """Tests for audit_token_issued."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_logs_token_issuance(self, mock_logger):
        from api.core.siam_audit import audit_token_issued

        audit_token_issued(
            session_id="sess-1",
            client_id="keycloak-1",
            ver_config_id="vc-1",
            claims_count=5,
            duration_ms=80,
        )

        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "token_issued"
        assert kw["claims_count"] == 5
        assert kw["client_id"] == "keycloak-1"


class TestAuditWebhookReceived:
    """Tests for audit_webhook_received."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_logs_webhook(self, mock_logger):
        from api.core.siam_audit import audit_webhook_received

        audit_webhook_received(
            topic="present_proof_v2_0",
            state="done",
            role="verifier",
        )

        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "webhook_received"
        assert kw["webhook_topic"] == "present_proof_v2_0"
        assert kw["webhook_state"] == "done"
        assert kw["webhook_role"] == "verifier"

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_optional_fields_omitted(self, mock_logger):
        from api.core.siam_audit import audit_webhook_received

        audit_webhook_received(topic="connections")

        kw = mock_logger.info.call_args[1]
        assert "webhook_state" not in kw
        assert "webhook_role" not in kw


class TestAuditInvalidClientRequest:
    """Tests for audit_invalid_client_request."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_logs_invalid_request(self, mock_logger):
        from api.core.siam_audit import audit_invalid_client_request

        audit_invalid_client_request(
            client_id="bad-client",
            error_type="unknown_client",
            client_ip="8.8.8.8",
        )

        kw = mock_logger.info.call_args[1]
        assert kw["audit_event_type"] == "invalid_client_request"
        assert kw["client_id"] == "bad-client"
        assert kw["error_type"] == "unknown_client"
        assert "client_ip_hash" in kw

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", True)
    def test_none_client_id(self, mock_logger):
        from api.core.siam_audit import audit_invalid_client_request

        audit_invalid_client_request(
            client_id=None,
            error_type="missing_params",
        )

        kw = mock_logger.info.call_args[1]
        assert "client_id" not in kw


# ===================================================================
# Feature flag integration
# ===================================================================


class TestFeatureFlag:
    """Test that SIAM_AUDIT_ENABLED properly gates all convenience functions."""

    @patch("api.core.siam_audit.logger")
    @patch("api.core.siam_audit.SIAM_AUDIT_ENABLED", False)
    def test_all_functions_suppressed_when_disabled(self, mock_logger):
        from api.core.siam_audit import (
            audit_auth_session_initiated,
            audit_invalid_client_request,
            audit_proof_request_created,
            audit_proof_verification_failed,
            audit_proof_verified,
            audit_qr_scanned,
            audit_session_abandoned,
            audit_session_expired,
            audit_token_issued,
            audit_webhook_received,
        )

        vc = _make_ver_config(schema_names=["Person"])

        audit_auth_session_initiated("s", "c", vc)
        audit_proof_request_created("s", vc)
        audit_qr_scanned("s", "qr_code")
        audit_proof_verified("s", "vc", ["Person"], ["did:sov:1"])
        audit_proof_verification_failed("s", "vc")
        audit_session_abandoned("s", "vc")
        audit_session_expired("s", "vc")
        audit_token_issued("s", "c", "vc", 3)
        audit_webhook_received("topic")
        audit_invalid_client_request("c", "err")

        mock_logger.info.assert_not_called()
