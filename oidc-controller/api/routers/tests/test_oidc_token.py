"""Tests for the OIDC token endpoint."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from api.authSessions.models import AuthSession
from api.verificationConfigs.models import VerificationConfig
from bson import ObjectId
from fastapi import HTTPException


@pytest.fixture
def mock_db():
    """Mock database fixture."""
    return MagicMock()


@pytest.fixture
def mock_auth_session():
    """Mock auth session fixture with presentation data."""
    auth_session = MagicMock(spec=AuthSession)
    auth_session.id = ObjectId()
    auth_session.pyop_user_id = "original-uuid-12345"
    auth_session.pyop_auth_code = "test-auth-code"
    auth_session.ver_config_id = "test-config-id"
    auth_session.request_parameters = {
        "pres_req_conf_id": "showcase-person",
        "nonce": "test-nonce-123",
    }
    auth_session.presentation_exchange = {
        "pres_request": {
            "indy": {
                "requested_attributes": {
                    "req_attr_0": {
                        "names": ["given_names", "family_name"],
                        "restrictions": [],
                    }
                }
            }
        },
        "pres": {
            "indy": {
                "requested_proof": {
                    "revealed_attr_groups": {
                        "req_attr_0": {
                            "sub_proof_index": 0,
                            "values": {
                                "given_names": {"raw": "John", "encoded": "123"},
                                "family_name": {"raw": "Doe", "encoded": "456"},
                            },
                        }
                    }
                }
            }
        },
    }
    return auth_session


@pytest.fixture
def mock_ver_config():
    """Mock verification config fixture."""
    config = MagicMock(spec=VerificationConfig)
    config.subject_identifier = "given_names"
    config.generate_consistent_identifier = False
    config.include_v1_attributes = False
    return config


@pytest.fixture
def mock_provider():
    """Mock PyOP provider fixture."""
    with patch("api.routers.oidc.provider") as mock:
        # Mock authorization codes storage
        authz_codes_mock = MagicMock()
        authz_codes_mock.__getitem__ = MagicMock(
            return_value={
                "sub": "original-uuid-12345",
                "client_id": "test-client",
            }
        )
        authz_codes_mock.pack = MagicMock(return_value="new-packed-code")

        # Mock subject identifiers storage
        subject_ids_mock = MagicMock()
        subject_ids_mock.__contains__ = MagicMock(return_value=False)
        subject_ids_mock.__setitem__ = MagicMock()

        # Mock userinfo
        userinfo_mock = MagicMock()
        userinfo_mock.set_claims_for_user = MagicMock()
        userinfo_mock.get_claims_for = MagicMock(
            return_value={
                "pres_req_conf_id": "showcase-person",
                "vc_presented_attributes": '{"given_names": "John"}',
            }
        )

        # Set up the provider structure
        mock.provider.authz_state.authorization_codes = authz_codes_mock
        mock.provider.authz_state.subject_identifiers = subject_ids_mock
        mock.provider.userinfo = userinfo_mock
        mock.provider.handle_token_request = MagicMock(
            return_value=MagicMock(
                to_dict=lambda: {
                    "access_token": "test-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "id_token": "test.id.token",
                }
            )
        )

        yield mock


class TestPostTokenSubjectReplacement:
    """Test subject replacement in post_token endpoint."""

    @pytest.mark.asyncio
    async def test_sub_is_replaced_with_presentation_sub(
        self, mock_db, mock_auth_session, mock_ver_config, mock_provider
    ):
        """Test that sub in authz_info is replaced with presentation_sub."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        # Mock CRUD operations
        with patch.object(
            AuthSessionCRUD, "get_by_pyop_auth_code", return_value=mock_auth_session
        ):
            with patch.object(
                VerificationConfigCRUD, "get", return_value=mock_ver_config
            ):
                with patch.object(
                    AuthSessionCRUD, "update_pyop_user_id", new_callable=AsyncMock
                ) as mock_update:
                    # Mock jwt.decode to avoid decoding errors
                    with patch("jwt.decode") as mock_decode:
                        mock_decode.return_value = {"sub": "John@showcase-person"}

                        # Create mock request with proper form context
                        mock_request = MagicMock()
                        mock_form = MagicMock()
                        mock_form._dict = {
                            "code": "test-auth-code",
                            "grant_type": "authorization_code",
                        }
                        mock_request.form = MagicMock(
                            return_value=MagicMock(
                                __aenter__=AsyncMock(return_value=mock_form),
                                __aexit__=AsyncMock(return_value=None),
                            )
                        )
                        mock_request.headers = {}

                        # Call the endpoint
                        await post_token(mock_request, mock_db)

                    # Verify AuthSession.pyop_user_id was updated
                    mock_update.assert_called_once()
                    call_args = mock_update.call_args
                    assert call_args[0][0] == str(mock_auth_session.id)
                    # presentation_sub is: given_names@pres_req_conf_id
                    expected_sub = "John@showcase-person"
                    assert call_args[0][1] == expected_sub

    @pytest.mark.asyncio
    async def test_claims_stored_with_presentation_sub_as_user_id(
        self, mock_db, mock_auth_session, mock_ver_config, mock_provider
    ):
        """Test that claims are stored with presentation_sub as user_id."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        with patch.object(
            AuthSessionCRUD,
            "get_by_pyop_auth_code",
            return_value=mock_auth_session,
        ):
            with patch.object(
                VerificationConfigCRUD, "get", return_value=mock_ver_config
            ):
                with patch.object(
                    AuthSessionCRUD,
                    "update_pyop_user_id",
                    new_callable=AsyncMock,
                ):
                    # Mock jwt.decode to avoid decoding errors
                    with patch("jwt.decode") as mock_decode:
                        mock_decode.return_value = {"sub": "John@showcase-person"}

                        mock_request = MagicMock()
                        mock_form = MagicMock()
                        mock_form._dict = {
                            "code": "test-auth-code",
                            "grant_type": "authorization_code",
                        }
                        mock_request.form = MagicMock(
                            return_value=MagicMock(
                                __aenter__=AsyncMock(return_value=mock_form),
                                __aexit__=AsyncMock(return_value=None),
                            )
                        )
                        mock_request.headers = {}

                        await post_token(mock_request, mock_db)

                        # Verify claims stored with presentation_sub
                        userinfo = mock_provider.provider.userinfo
                        userinfo.set_claims_for_user.assert_called_once()

                        call_args = userinfo.set_claims_for_user.call_args
                        stored_user_id = call_args[0][0]
                        stored_claims = call_args[0][1]

                        # User ID should be the presentation_sub
                        assert stored_user_id == "John@showcase-person"

                        # Claims contain VC attributes but NOT sub
                        assert "pres_req_conf_id" in stored_claims
                        assert "vc_presented_attributes" in stored_claims
                        # Critical: no duplicate sub
                        assert "sub" not in stored_claims
                        
                        # Verify authz_info["user_info"] was updated for StatelessWrapper
                        authz_codes = mock_provider.provider.authz_state.authorization_codes
                        pack_call_args = authz_codes.pack.call_args[0][0]
                        assert "user_info" in pack_call_args
                        assert pack_call_args["user_info"] == stored_claims

    @pytest.mark.asyncio
    async def test_sub_not_included_in_userinfo_claims(
        self, mock_db, mock_auth_session, mock_ver_config, mock_provider
    ):
        """Test sub is NOT in claims stored in VCUserinfo."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        with patch.object(
            AuthSessionCRUD,
            "get_by_pyop_auth_code",
            return_value=mock_auth_session,
        ):
            with patch.object(
                VerificationConfigCRUD, "get", return_value=mock_ver_config
            ):
                with patch.object(
                    AuthSessionCRUD,
                    "update_pyop_user_id",
                    new_callable=AsyncMock,
                ):
                    # Mock jwt.decode to avoid decoding errors
                    with patch("jwt.decode") as mock_decode:
                        mock_decode.return_value = {"sub": "John@showcase-person"}

                        mock_request = MagicMock()
                        mock_form = MagicMock()
                        mock_form._dict = {
                            "code": "test-auth-code",
                            "grant_type": "authorization_code",
                        }
                        mock_request.form = MagicMock(
                            return_value=MagicMock(
                                __aenter__=AsyncMock(return_value=mock_form),
                                __aexit__=AsyncMock(return_value=None),
                            )
                        )
                        mock_request.headers = {}

                        await post_token(mock_request, mock_db)

                        # Get the claims that were stored
                        userinfo = mock_provider.provider.userinfo
                        stored_claims = userinfo.set_claims_for_user.call_args[0][1]

                        # Verify sub is NOT in stored claims
                        assert "sub" not in stored_claims


class TestPostTokenClaimsInclusion:
    """Test that custom claims are included in token response."""

    @pytest.mark.asyncio
    async def test_custom_claims_are_stored_in_userinfo(
        self, mock_db, mock_auth_session, mock_ver_config, mock_provider
    ):
        """Test pres_req_conf_id and vc_presented_attributes stored."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        with patch.object(
            AuthSessionCRUD,
            "get_by_pyop_auth_code",
            return_value=mock_auth_session,
        ):
            with patch.object(
                VerificationConfigCRUD, "get", return_value=mock_ver_config
            ):
                with patch.object(
                    AuthSessionCRUD,
                    "update_pyop_user_id",
                    new_callable=AsyncMock,
                ):
                    # Mock jwt.decode to avoid decoding errors
                    with patch("jwt.decode") as mock_decode:
                        mock_decode.return_value = {"sub": "John@showcase-person"}

                        mock_request = MagicMock()
                        mock_form = MagicMock()
                        mock_form._dict = {
                            "code": "test-auth-code",
                            "grant_type": "authorization_code",
                        }
                        mock_request.form = MagicMock(
                            return_value=MagicMock(
                                __aenter__=AsyncMock(return_value=mock_form),
                                __aexit__=AsyncMock(return_value=None),
                            )
                        )
                        mock_request.headers = {}

                        await post_token(mock_request, mock_db)

                        userinfo = mock_provider.provider.userinfo
                        stored_claims = userinfo.set_claims_for_user.call_args[0][1]

                        # Verify custom claims are present
                        conf_id = stored_claims["pres_req_conf_id"]
                        assert conf_id == "showcase-person"
                        assert "vc_presented_attributes" in stored_claims
                        assert "acr" in stored_claims
                        assert stored_claims["acr"] == "vc_authn"

    @pytest.mark.asyncio
    async def test_missing_pyop_user_id_raises_error(
        self, mock_db, mock_auth_session, mock_ver_config, mock_provider
    ):
        """Test that missing pyop_user_id raises HTTPException."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        # Set pyop_user_id to None
        mock_auth_session.pyop_user_id = None

        with patch.object(
            AuthSessionCRUD,
            "get_by_pyop_auth_code",
            return_value=mock_auth_session,
        ):
            with patch.object(
                VerificationConfigCRUD, "get", return_value=mock_ver_config
            ):
                mock_request = MagicMock()
                mock_form = MagicMock()
                mock_form._dict = {
                    "code": "test-auth-code",
                    "grant_type": "authorization_code",
                }
                mock_request.form = MagicMock(
                    return_value=MagicMock(
                        __aenter__=AsyncMock(return_value=mock_form),
                        __aexit__=AsyncMock(return_value=None),
                    )
                )
                mock_request.headers = {}

                # Should raise HTTPException
                with pytest.raises(HTTPException) as exc_info:
                    await post_token(mock_request, mock_db)

                assert exc_info.value.status_code == 500
                assert "pyop_user_id" in exc_info.value.detail


class TestPostTokenConsistentIdentifier:
    """Test consistent identifier generation."""

    @pytest.mark.asyncio
    async def test_consistent_identifier_used_when_no_matching_attribute(
        self, mock_db, mock_auth_session, mock_provider
    ):
        """Test consistent ID when subject_identifier doesn't match."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        # Config with non-matching subject_identifier
        mock_config = MagicMock()
        mock_config.subject_identifier = "email"  # Not in presentation
        mock_config.generate_consistent_identifier = True
        mock_config.include_v1_attributes = False

        with patch.object(
            AuthSessionCRUD,
            "get_by_pyop_auth_code",
            return_value=mock_auth_session,
        ):
            with patch.object(VerificationConfigCRUD, "get", return_value=mock_config):
                with patch.object(
                    AuthSessionCRUD,
                    "update_pyop_user_id",
                    new_callable=AsyncMock,
                ) as mock_update:
                    # Mock jwt.decode to avoid decoding errors
                    with patch("jwt.decode") as mock_decode:
                        # Hash for test data
                        test_hash = (
                            "26b555bc1867e8b9f2eaa9685e028a20"
                            "dde9ad85d40690b84295c6dafbba629b"
                        )
                        mock_decode.return_value = {"sub": test_hash}

                        mock_request = MagicMock()
                        mock_form = MagicMock()
                        mock_form._dict = {
                            "code": "test-auth-code",
                            "grant_type": "authorization_code",
                        }
                        mock_request.form = MagicMock(
                            return_value=MagicMock(
                                __aenter__=AsyncMock(return_value=mock_form),
                                __aexit__=AsyncMock(return_value=None),
                            )
                        )
                        mock_request.headers = {}

                        await post_token(mock_request, mock_db)

                        # Should have generated a hash-based identifier
                        call_args = mock_update.call_args[0]
                        generated_sub = call_args[1]

                        # Should be a hex hash (64 chars for SHA256)
                        assert len(generated_sub) == 64
                        assert all(c in "0123456789abcdef" for c in generated_sub)


class TestPostTokenErrorHandling:
    """Test error handling in post_token endpoint."""

    @pytest.mark.asyncio
    async def test_claims_storage_exception_raises_http_exception(
        self, mock_db, mock_auth_session, mock_ver_config, mock_provider
    ):
        """Test that exception in set_claims_for_user raises HTTPException."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        # Make userinfo.set_claims_for_user raise an exception
        mock_provider.provider.userinfo.set_claims_for_user.side_effect = RuntimeError(
            "Redis connection failed"
        )

        with patch.object(
            AuthSessionCRUD,
            "get_by_pyop_auth_code",
            return_value=mock_auth_session,
        ):
            with patch.object(
                VerificationConfigCRUD, "get", return_value=mock_ver_config
            ):
                with patch.object(
                    AuthSessionCRUD,
                    "update_pyop_user_id",
                    new_callable=AsyncMock,
                ):
                    # Mock jwt.decode to avoid decoding errors
                    with patch("jwt.decode") as mock_decode:
                        mock_decode.return_value = {"sub": "John@showcase-person"}

                        mock_request = MagicMock()
                        mock_form = MagicMock()
                        mock_form._dict = {
                            "code": "test-auth-code",
                            "grant_type": "authorization_code",
                        }
                        mock_request.form = MagicMock(
                            return_value=MagicMock(
                                __aenter__=AsyncMock(return_value=mock_form),
                                __aexit__=AsyncMock(return_value=None),
                            )
                        )
                        mock_request.headers = {}

                        # Should raise HTTPException with 500 status
                        with pytest.raises(HTTPException) as exc_info:
                            await post_token(mock_request, mock_db)

                        assert exc_info.value.status_code == 500
                        assert "Failed to store claims" in exc_info.value.detail
                        assert "Redis connection failed" in exc_info.value.detail


class TestPostTokenStatelessWrapper:
    """Test StatelessWrapper-specific behavior in post_token endpoint."""

    @pytest.mark.asyncio
    async def test_authz_info_user_info_updated_before_pack(
        self, mock_db, mock_auth_session, mock_ver_config, mock_provider
    ):
        """Test that authz_info['user_info'] is updated with claims before packing."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        with patch.object(
            AuthSessionCRUD,
            "get_by_pyop_auth_code",
            return_value=mock_auth_session,
        ):
            with patch.object(
                VerificationConfigCRUD, "get", return_value=mock_ver_config
            ):
                with patch.object(
                    AuthSessionCRUD,
                    "update_pyop_user_id",
                    new_callable=AsyncMock,
                ):
                    with patch("jwt.decode") as mock_decode:
                        mock_decode.return_value = {"sub": "John@showcase-person"}

                        mock_request = MagicMock()
                        mock_form = MagicMock()
                        mock_form._dict = {
                            "code": "test-auth-code",
                            "grant_type": "authorization_code",
                        }
                        mock_request.form = MagicMock(
                            return_value=MagicMock(
                                __aenter__=AsyncMock(return_value=mock_form),
                                __aexit__=AsyncMock(return_value=None),
                            )
                        )
                        mock_request.headers = {}

                        await post_token(mock_request, mock_db)

                        # Verify authz_info was packed with user_info field
                        authz_codes = mock_provider.provider.authz_state.authorization_codes
                        authz_codes.pack.assert_called_once()
                        
                        packed_authz_info = authz_codes.pack.call_args[0][0]
                        
                        # Critical: user_info field must be present and contain claims
                        assert "user_info" in packed_authz_info
                        user_info = packed_authz_info["user_info"]
                        
                        # Verify user_info contains the presentation claims
                        assert "pres_req_conf_id" in user_info
                        assert user_info["pres_req_conf_id"] == "showcase-person"
                        assert "vc_presented_attributes" in user_info
                        assert "acr" in user_info
                        
                        # Verify sub is NOT in user_info (it goes in authz_info["sub"])
                        assert "sub" not in user_info

    @pytest.mark.asyncio
    async def test_authz_info_sub_updated_with_presentation_sub(
        self, mock_db, mock_auth_session, mock_ver_config, mock_provider
    ):
        """Test that authz_info['sub'] is updated with presentation subject."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        with patch.object(
            AuthSessionCRUD,
            "get_by_pyop_auth_code",
            return_value=mock_auth_session,
        ):
            with patch.object(
                VerificationConfigCRUD, "get", return_value=mock_ver_config
            ):
                with patch.object(
                    AuthSessionCRUD,
                    "update_pyop_user_id",
                    new_callable=AsyncMock,
                ):
                    with patch("jwt.decode") as mock_decode:
                        mock_decode.return_value = {"sub": "John@showcase-person"}

                        mock_request = MagicMock()
                        mock_form = MagicMock()
                        mock_form._dict = {
                            "code": "test-auth-code",
                            "grant_type": "authorization_code",
                        }
                        mock_request.form = MagicMock(
                            return_value=MagicMock(
                                __aenter__=AsyncMock(return_value=mock_form),
                                __aexit__=AsyncMock(return_value=None),
                            )
                        )
                        mock_request.headers = {}

                        await post_token(mock_request, mock_db)

                        # Verify authz_info["sub"] was updated before packing
                        authz_codes = mock_provider.provider.authz_state.authorization_codes
                        packed_authz_info = authz_codes.pack.call_args[0][0]
                        
                        assert packed_authz_info["sub"] == "John@showcase-person"

    @pytest.mark.asyncio
    async def test_user_info_contains_all_presentation_attributes(
        self, mock_db, mock_auth_session, mock_ver_config, mock_provider
    ):
        """Test that user_info in authz_info contains all presentation attributes."""
        from api.authSessions.crud import AuthSessionCRUD
        from api.routers.oidc import post_token
        from api.verificationConfigs.crud import VerificationConfigCRUD

        with patch.object(
            AuthSessionCRUD,
            "get_by_pyop_auth_code",
            return_value=mock_auth_session,
        ):
            with patch.object(
                VerificationConfigCRUD, "get", return_value=mock_ver_config
            ):
                with patch.object(
                    AuthSessionCRUD,
                    "update_pyop_user_id",
                    new_callable=AsyncMock,
                ):
                    with patch("jwt.decode") as mock_decode:
                        mock_decode.return_value = {"sub": "John@showcase-person"}

                        mock_request = MagicMock()
                        mock_form = MagicMock()
                        mock_form._dict = {
                            "code": "test-auth-code",
                            "grant_type": "authorization_code",
                        }
                        mock_request.form = MagicMock(
                            return_value=MagicMock(
                                __aenter__=AsyncMock(return_value=mock_form),
                                __aexit__=AsyncMock(return_value=None),
                            )
                        )
                        mock_request.headers = {}

                        await post_token(mock_request, mock_db)

                        # Get the user_info that was packed into authz_info
                        authz_codes = mock_provider.provider.authz_state.authorization_codes
                        packed_authz_info = authz_codes.pack.call_args[0][0]
                        user_info = packed_authz_info["user_info"]
                        
                        # Verify all expected attributes are present
                        expected_keys = [
                            "pres_req_conf_id",
                            "vc_presented_attributes",
                            "acr",
                        ]
                        for key in expected_keys:
                            assert key in user_info, f"Missing expected key: {key}"
                        
                        # Verify values
                        assert user_info["pres_req_conf_id"] == "showcase-person"
                        assert user_info["acr"] == "vc_authn"
                        assert "given_names" in user_info["vc_presented_attributes"]
                        assert "family_name" in user_info["vc_presented_attributes"]
