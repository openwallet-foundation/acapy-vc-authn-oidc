import pytest
import json

from api.core.oidc.issue_token_service import Token
from api.core.oidc.tests.__mocks__ import auth_session, presentation, ver_config

from copy import deepcopy
from api.core.config import settings
from unittest.mock import patch

basic_valid_requested_attributes = {
    "req_attr_0": {
        "names": ["email"],
        "restrictions": [
            {
                "schema_name": "verified-email",
                "issuer_did": "MTYqmTBoLT7KLP5RNfgK3b",
            }
        ],
    }
}

basic_valid_revealed_attr_groups = {
    "req_attr_0": {
        "sub_proof_index": 0,
        "values": {
            "email": {
                "raw": "test@email.com",
                "encoded": (
                    "738146027672528685612682618324628725772931091843279086604002484444"
                    "58427915643"
                ),
            }
        },
    }
}

multiple_valid_requested_attributes = {
    "req_attr_0": {
        "names": ["email_1", "age_1"],
        "restrictions": [
            {
                "schema_name": "verified-email",
                "issuer_did": "MTYqmTBoLT7KLP5RNfgK3b",
            }
        ],
    },
}

multiple_valid_revealed_attr_groups = {
    "req_attr_0": {
        "sub_proof_index": 0,
        "values": {
            "email_1": {
                "raw": "test@email.com",
                "encoded": (
                    "738146027672528685612682618324628725772931091843279086604002484444"
                    "58427915643"
                ),
            },
            "age_1": {
                "raw": "30",
                "encoded": (
                    "738146027672528685612682618324628725772931091843279086604002484444"
                    "58427915643"
                ),
            },
        },
    }
}


@pytest.mark.asyncio
async def test_valid_proof_presentation_with_one_attribute_returns_claims():
    presentation["by_format"]["pres_request"]["indy"][
        "requested_attributes"
    ] = basic_valid_requested_attributes
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = basic_valid_revealed_attr_groups
    auth_session.presentation_exchange = presentation["by_format"]
    claims = Token.get_claims(auth_session, ver_config)
    assert claims is not None


@pytest.mark.asyncio
async def test_valid_proof_presentation_with_multiple_attributes_returns_claims():
    presentation["by_format"]["pres_request"]["indy"]["requested_attributes"] = {
        "req_attr_0": {
            "names": ["email"],
            "restrictions": [
                {
                    "schema_name": "verified-email",
                    "issuer_did": "MTYqmTBoLT7KLP5RNfgK3b",
                }
            ],
        },
        "req_attr_1": {
            "names": ["age"],
            "restrictions": [
                {
                    "schema_name": "verified-age",
                    "issuer_did": "MTYqmTBoLT7KLP5RNfgK3c",
                }
            ],
        },
    }
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = {
        "req_attr_0": {
            "sub_proof_index": 0,
            "values": {
                "email": {
                    "raw": "test@email.com",
                    "encoded": (
                        "73814602767252868561268261832462872577293109184327908660400"
                        "248444458427915643"
                    ),
                }
            },
        },
        "req_attr_1": {
            "sub_proof_index": 0,
            "values": {
                "age": {
                    "raw": "30",
                    "encoded": (
                        "73814602767252868561268261832462872577293109184327908660400"
                        "248444458427915643"
                    ),
                }
            },
        },
    }
    auth_session.presentation_exchange = presentation["by_format"]
    claims = Token.get_claims(auth_session, ver_config)
    assert claims is not None


@pytest.mark.asyncio
async def test_include_v1_attributes_false_does_not_add_the_named_attributes():
    presentation["by_format"]["pres_request"]["indy"][
        "requested_attributes"
    ] = multiple_valid_requested_attributes
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = multiple_valid_revealed_attr_groups
    auth_session.presentation_exchange = presentation["by_format"]
    ver_config.include_v1_attributes = False
    claims = Token.get_claims(auth_session, ver_config)
    vc_presented_attributes_obj = eval(claims["vc_presented_attributes"])
    assert claims is not None
    assert vc_presented_attributes_obj["email_1"] == "test@email.com"
    assert vc_presented_attributes_obj["age_1"] == "30"
    assert "email_1" not in claims
    assert "age_1" not in claims


@pytest.mark.asyncio
async def test_include_v1_attributes_true_adds_the_named_attributes():
    presentation["by_format"]["pres_request"]["indy"][
        "requested_attributes"
    ] = multiple_valid_requested_attributes
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = multiple_valid_revealed_attr_groups
    auth_session.presentation_exchange = presentation["by_format"]
    ver_config.include_v1_attributes = True
    claims = Token.get_claims(auth_session, ver_config)
    vc_presented_attributes_obj = eval(claims["vc_presented_attributes"])
    assert claims is not None
    assert vc_presented_attributes_obj["email_1"] == "test@email.com"
    assert vc_presented_attributes_obj["age_1"] == "30"
    assert claims["email_1"] == "test@email.com"
    assert claims["age_1"] == "30"


@pytest.mark.asyncio
async def test_include_v1_attributes_none_does_not_add_the_named_attributes():
    presentation["by_format"]["pres_request"]["indy"][
        "requested_attributes"
    ] = multiple_valid_requested_attributes
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = multiple_valid_revealed_attr_groups
    auth_session.presentation_exchange = presentation["by_format"]
    ver_config.include_v1_attributes = None
    print(ver_config.include_v1_attributes)
    claims = Token.get_claims(auth_session, ver_config)
    vc_presented_attributes_obj = eval(claims["vc_presented_attributes"])
    assert claims is not None
    assert vc_presented_attributes_obj["email_1"] == "test@email.com"
    assert vc_presented_attributes_obj["age_1"] == "30"
    assert "email_1" not in claims
    assert "age_1" not in claims


@pytest.mark.asyncio
async def test_revealed_attrs_dont_match_requested_attributes_throws_exception():
    presentation["by_format"]["pres_request"]["indy"]["requested_attributes"] = {
        "req_attr_0": {
            "names": ["email"],
            "restrictions": [
                {
                    "schema_name": "verified-email",
                    "issuer_did": "MTYqmTBoLT7KLP5RNfgK3b",
                }
            ],
        }
    }
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = {
        "req_attr_0": {
            "sub_proof_index": 0,
            "values": {
                "email-wrong": {
                    "raw": "test@email.com",
                    "encoded": (
                        "73814602767252868561268261832462872577293109184327908660400"
                        "248444458427915643"
                    ),
                }
            },
        }
    }
    auth_session.presentation_exchange = presentation["by_format"]
    with pytest.raises(Exception):
        Token.get_claims(auth_session, ver_config)


@pytest.mark.asyncio
async def test_valid_presentation_with_matching_subject_identifier_in_claims_sub():
    presentation["by_format"]["pres_request"]["indy"][
        "requested_attributes"
    ] = basic_valid_requested_attributes
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = basic_valid_revealed_attr_groups
    auth_session.presentation_exchange = presentation["by_format"]
    claims = Token.get_claims(auth_session, ver_config)
    print(claims)
    assert claims["sub"] == "test@email.com@verified-email"


@pytest.mark.asyncio
async def test_valid_pres_with_non_matching_subj_id_gen_consistent_id_missing_no_sub():
    presentation["by_format"]["pres_request"]["indy"][
        "requested_attributes"
    ] = basic_valid_requested_attributes
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = basic_valid_revealed_attr_groups
    auth_session.presentation_exchange = presentation["by_format"]
    ver_config.subject_identifier = "not-email"
    claims = Token.get_claims(auth_session, ver_config)
    assert not ver_config.generate_consistent_identifier
    assert "sub" not in claims


@pytest.mark.asyncio
async def test_valid_pres_non_matching_subj_id_gen_consistent_id_false_has_no_sub():
    presentation["by_format"]["pres_request"]["indy"][
        "requested_attributes"
    ] = basic_valid_requested_attributes
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = basic_valid_revealed_attr_groups
    auth_session.presentation_exchange = presentation["by_format"]
    ver_config.subject_identifier = "not-email"
    ver_config.generate_consistent_identifier = False
    claims = Token.get_claims(auth_session, ver_config)
    assert "sub" not in claims


@pytest.mark.asyncio
async def test_valid_pres_non_matching_subj_id_gen_consistent_id_true_has_sub():
    presentation["by_format"]["pres_request"]["indy"][
        "requested_attributes"
    ] = basic_valid_requested_attributes
    presentation["by_format"]["pres"]["indy"]["requested_proof"][
        "revealed_attr_groups"
    ] = basic_valid_revealed_attr_groups
    auth_session.presentation_exchange = presentation["by_format"]
    ver_config.subject_identifier = "not-email"
    ver_config.generate_consistent_identifier = True
    claims = Token.get_claims(auth_session, ver_config)
    assert "sub" in claims

    # Ensure that this sub is not using the ver_config.subject_identifier
    ver_config.subject_identifier = "email"
    ver_config.generate_consistent_identifier = False
    claims_subject_identifier = Token.get_claims(auth_session, ver_config)
    assert claims["sub"] != claims_subject_identifier["sub"]

    # Ensure that sub is consistent
    ver_config.subject_identifier = "not-email"
    ver_config.generate_consistent_identifier = True
    claims_duplicate = Token.get_claims(auth_session, ver_config)
    assert claims["sub"] == claims_duplicate["sub"]


def test_idtoken_dict_creates_proper_structure():
    """Test that idtoken_dict() creates properly formatted ID token dictionary."""
    # Create a Token instance with test claims including vc_presented_attributes
    # Note: 'sub' is required by OpenIDSchema
    test_claims = {
        "pres_req_conf_id": "test_config",
        "acr": "vc_authn",
        "vc_presented_attributes": '{"email": "test@example.com", "name": "Test User", "sub": "user123"}',
    }

    token = Token(
        issuer="https://test-issuer.com",
        audiences=["test-client-id"],
        lifetime=3600,
        claims=test_claims,
    )

    # Call idtoken_dict with a nonce
    nonce = "test-nonce-12345"
    result = token.idtoken_dict(nonce)

    # Verify required ID token fields
    assert "exp" in result
    assert "aud" in result
    assert "nonce" in result
    assert result["aud"] == ["test-client-id"]
    assert result["nonce"] == nonce

    # Verify claims are included
    assert result["pres_req_conf_id"] == "test_config"
    assert result["acr"] == "vc_authn"

    # Verify standard claims are extracted to top level
    assert "email" in result
    assert result["email"] == "test@example.com"
    assert "sub" in result
    assert result["sub"] == "user123"


def test_idtoken_dict_includes_standard_openid_claims():
    """Test that idtoken_dict extracts OpenID standard claims to top level."""
    # Create claims with various OpenID standard claims in vc_presented_attributes
    test_claims = {
        "pres_req_conf_id": "test_config",
        "vc_presented_attributes": '{"email": "user@example.com", "given_name": "John", "family_name": "Doe", "sub": "johndoe123", "custom_claim": "should_not_be_extracted"}',
    }

    token = Token(
        issuer="https://test-issuer.com",
        audiences=["client1", "client2"],
        lifetime=7200,
        claims=test_claims,
    )

    result = token.idtoken_dict("nonce-value")

    # Verify standard OpenID claims are at top level
    assert "email" in result
    assert result["email"] == "user@example.com"
    assert "given_name" in result
    assert result["given_name"] == "John"
    assert "family_name" in result
    assert result["family_name"] == "Doe"
    assert "sub" in result
    assert result["sub"] == "johndoe123"

    # Verify custom claims are NOT extracted to top level (only in vc_presented_attributes)
    # OpenIDSchema only validates known OpenID Connect standard claims
    assert "custom_claim" not in result or result.get("custom_claim") is None

# Helper to construct mock data with specific structure keys using local test data
def create_mock_presentation_exchange(format_key="indy"):
    return {
        "pres_request": {
            format_key: {
                "requested_attributes": basic_valid_requested_attributes
            }
        },
        "pres": {
            format_key: {
                "requested_proof": {
                    "revealed_attr_groups": basic_valid_revealed_attr_groups
                }
            }
        }
    }

@pytest.mark.asyncio
async def test_get_claims_happy_path_anoncreds():
    """Test extracting claims when config is anoncreds and data matches."""
    # Arrange: Data has 'anoncreds' key
    auth_session.presentation_exchange = create_mock_presentation_exchange("anoncreds")
    
    # Act: Config is 'anoncreds'
    with patch.object(settings, "ACAPY_PROOF_FORMAT", "anoncreds"):
        claims = Token.get_claims(auth_session, ver_config)
        
    # Assert
    attributes = json.loads(claims["vc_presented_attributes"])
    assert attributes["email"] == "test@email.com"

@pytest.mark.asyncio
async def test_get_claims_fallback_migration_logic():
    """
    Critical Test: Verify migration fallback.
    Config is set to 'anoncreds' (new), but DB record has 'indy' (old).
    """
    # Arrange: Data only has 'indy' key (simulating old record in DB)
    auth_session.presentation_exchange = create_mock_presentation_exchange("indy")
    
    # Act: Config is set to 'anoncreds' (simulating new deployment)
    with patch.object(settings, "ACAPY_PROOF_FORMAT", "anoncreds"):
        # This would raise KeyError if fallback logic didn't exist
        claims = Token.get_claims(auth_session, ver_config)
        
    # Assert: Should still find the data under 'indy' key
    attributes = json.loads(claims["vc_presented_attributes"])
    assert attributes["email"] == "test@email.com"