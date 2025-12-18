"""Tests for subject identifier management and reverse mapping cleanup."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from api.authSessions.models import AuthSession
from bson import ObjectId
from api.routers.oidc import store_subject_identifier
from api.routers.oidc import post_token


class TestStoreSubjectIdentifier:
    """Tests for store_subject_identifier function with reverse mapping cleanup."""

    def test_stores_new_subject_identifier_without_cleanup(self):
        """Test storing a new subject identifier when no previous mapping exists."""

        # Create mock provider structure
        mock_storage = MagicMock()
        mock_storage.__contains__ = MagicMock(return_value=False)
        mock_storage.__getitem__ = MagicMock(
            side_effect=KeyError("reverse mapping not found")
        )
        mock_storage.__setitem__ = MagicMock()

        mock_provider_obj = MagicMock()
        mock_provider_obj.authz_state.subject_identifiers = mock_storage

        # Patch settings where store_subject_identifier imports it (inside the function)
        with patch("api.core.config.settings") as mock_settings, patch(
            "api.routers.oidc.provider"
        ) as mock_provider:
            mock_settings.USE_REDIS_ADAPTER = True
            mock_provider.provider = mock_provider_obj

            # Execute
            is_new = store_subject_identifier(
                "alice@example.com@showcase-person",
                "public",
                "alice@example.com@showcase-person",
            )

            # Verify
            assert is_new is True
            # Should store reverse mapping
            assert mock_storage.__setitem__.call_count >= 1
            # Verify reverse mapping was stored
            reverse_calls = [
                call
                for call in mock_storage.__setitem__.call_args_list
                if "reverse:" in str(call[0][0])
            ]
            assert len(reverse_calls) == 1

    def test_cleans_up_stale_subject_identifier_on_relogin(self):
        """Test that stale subject identifiers are cleaned up when same user logs in again."""

        # Simulate existing reverse mapping pointing to old UUID
        old_user_id = "old-uuid-12345"
        new_user_id = "alice@example.com@showcase-person"
        presentation_sub = "alice@example.com@showcase-person"
        reverse_key = f"reverse:{presentation_sub}"

        # Mock storage with stale mapping
        def mock_getitem(key):
            if key == reverse_key:
                return old_user_id  # Reverse mapping points to old UUID
            raise KeyError(f"Key {key} not found")

        mock_storage = MagicMock()
        mock_storage.__getitem__ = MagicMock(side_effect=mock_getitem)
        mock_storage.__delitem__ = MagicMock()
        mock_storage.__setitem__ = MagicMock()
        mock_storage.__contains__ = MagicMock(return_value=False)

        mock_provider_obj = MagicMock()
        mock_provider_obj.authz_state.subject_identifiers = mock_storage

        # Patch settings where store_subject_identifier imports it (inside the function)
        with patch("api.core.config.settings") as mock_settings, patch(
            "api.routers.oidc.provider"
        ) as mock_provider:
            mock_settings.USE_REDIS_ADAPTER = True
            mock_provider.provider = mock_provider_obj

            # Execute - user logs in again with same presentation_sub
            is_new = store_subject_identifier(new_user_id, "public", presentation_sub)

            # Verify
            assert is_new is True
            # Should delete the stale mapping (old UUID)
            mock_storage.__delitem__.assert_called_once_with(old_user_id)
            # Should store new reverse mapping
            assert any(
                call[0][0] == reverse_key
                for call in mock_storage.__setitem__.call_args_list
            )

    def test_does_not_cleanup_if_same_user_id(self):
        """Test that no cleanup occurs if reverse mapping already points to current user_id."""
        with patch("api.routers.oidc.provider") as mock_provider, patch(
            "api.routers.oidc.settings"
        ) as mock_settings:
            # Setup
            mock_settings.USE_REDIS_ADAPTER = True
            mock_storage = MagicMock()
            mock_provider.provider.authz_state.subject_identifiers = mock_storage

            user_id = "alice@example.com@showcase-person"
            presentation_sub = "alice@example.com@showcase-person"
            reverse_key = f"reverse:{presentation_sub}"

            # Reverse mapping already points to current user_id
            def mock_getitem(key):
                if key == reverse_key:
                    return user_id  # Already correct
                if key == user_id:
                    return {"public": presentation_sub}
                raise KeyError(f"Key {key} not found")

            mock_storage.__getitem__ = MagicMock(side_effect=mock_getitem)
            mock_storage.__contains__ = MagicMock(return_value=True)
            mock_storage.__delitem__ = MagicMock()
            mock_storage.__setitem__ = MagicMock()

            # Execute
            is_new = store_subject_identifier(user_id, "public", presentation_sub)

            # Verify
            assert is_new is False
            # Should NOT delete anything (reverse mapping already correct)
            mock_storage.__delitem__.assert_not_called()

    def test_skips_cleanup_in_stateless_mode(self):
        """Test that reverse mapping cleanup is skipped when using StatelessWrapper."""
        with patch("api.routers.oidc.provider") as mock_provider, patch(
            "api.routers.oidc.settings"
        ) as mock_settings:
            # Setup - StatelessWrapper mode (no Redis)
            mock_settings.USE_REDIS_ADAPTER = False
            mock_storage = MagicMock()
            mock_provider.provider.authz_state.subject_identifiers = mock_storage

            mock_storage.__contains__ = MagicMock(return_value=False)
            mock_storage.__getitem__ = MagicMock(side_effect=KeyError())
            mock_storage.__setitem__ = MagicMock()

            # Execute
            store_subject_identifier(
                "user-123", "public", "alice@example.com@showcase-person"
            )

            # Verify - should NOT attempt reverse mapping operations
            # Only stores the forward mapping
            calls = mock_storage.__setitem__.call_args_list
            reverse_calls = [call for call in calls if "reverse:" in str(call)]
            assert len(reverse_calls) == 0


class TestPostTokenAuthSessionUpdate:
    """Tests for AuthSession.pyop_user_id update during post_token."""

    @pytest.mark.asyncio
    async def test_updates_auth_session_pyop_user_id_to_presentation_sub(self):
        """Test that AuthSession.pyop_user_id is updated to presentation_sub."""
        with patch("api.routers.oidc.AuthSessionCRUD") as mock_crud_class, patch(
            "api.routers.oidc.VerificationConfigCRUD"
        ) as mock_ver_crud_class, patch(
            "api.routers.oidc.provider"
        ) as mock_provider, patch(
            "api.routers.oidc.Token"
        ) as mock_token_class, patch(
            "api.routers.oidc.settings"
        ) as mock_settings:
            # Setup mocks
            mock_settings.USE_REDIS_ADAPTER = True
            mock_settings.ACAPY_PROOF_FORMAT = "anoncreds"

            mock_auth_session = MagicMock(spec=AuthSession)
            mock_auth_session.id = ObjectId()
            mock_auth_session.pyop_user_id = "original-uuid-12345"
            mock_auth_session.pyop_auth_code = "test-code"
            mock_auth_session.ver_config_id = "test-config"
            mock_auth_session.request_parameters = {
                "pres_req_conf_id": "showcase-person",
                "nonce": "test-nonce",
            }
            mock_auth_session.presentation_exchange = {
                "pres_request": {
                    "anoncreds": {
                        "requested_attributes": {"req_attr_0": {"names": ["email"]}}
                    }
                },
                "pres": {
                    "anoncreds": {
                        "requested_proof": {
                            "revealed_attr_groups": {
                                "req_attr_0": {
                                    "values": {
                                        "email": {
                                            "raw": "alice@example.com",
                                            "encoded": "123",
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }

            mock_ver_config = MagicMock()
            mock_ver_config.subject_identifier = "email"
            mock_ver_config.generate_consistent_identifier = False

            # Mock Token.get_claims to return claims with sub
            mock_token_class.get_claims.return_value = {
                "sub": "alice@example.com@showcase-person",
                "pres_req_conf_id": "showcase-person",
                "acr": "vc_authn",
                "nonce": "test-nonce",
                "vc_presented_attributes": '{"email": "alice@example.com"}',
            }

            # Mock CRUD
            mock_crud = MagicMock()
            mock_crud.get_by_pyop_auth_code = AsyncMock(return_value=mock_auth_session)
            mock_crud.update_pyop_user_id = AsyncMock(return_value=True)
            mock_crud_class.return_value = mock_crud

            mock_ver_crud = MagicMock()
            mock_ver_crud.get = AsyncMock(return_value=mock_ver_config)
            mock_ver_crud_class.return_value = mock_ver_crud

            # Mock PyOP provider
            mock_authz_codes = MagicMock()
            mock_authz_info = {
                "sub": "original-uuid-12345",
                "user_info": {},
            }
            mock_authz_codes.__getitem__ = MagicMock(return_value=mock_authz_info)
            mock_authz_codes.pack = MagicMock(return_value="new-packed-code")
            mock_provider.provider.authz_state.authorization_codes = mock_authz_codes

            # Mock userinfo with set_claims_for_user method
            mock_userinfo = MagicMock()
            mock_userinfo.set_claims_for_user = MagicMock()
            mock_provider.provider.userinfo = mock_userinfo

            mock_provider.provider.handle_token_request = MagicMock(
                return_value=MagicMock(to_dict=lambda: {"access_token": "test-token"})
            )

            # Mock request with async context manager for form()
            mock_request = MagicMock()
            mock_form = MagicMock()
            mock_form._dict = {
                "code": "test-code",
                "grant_type": "authorization_code",
            }
            # Mock form() as async context manager
            mock_form_context = AsyncMock()
            mock_form_context.__aenter__ = AsyncMock(return_value=mock_form)
            mock_form_context.__aexit__ = AsyncMock(return_value=None)
            mock_request.form = MagicMock(return_value=mock_form_context)

            mock_db = MagicMock()

            # Execute
            await post_token(mock_request, mock_db)

            # Verify AuthSession.pyop_user_id was updated to presentation_sub
            mock_crud.update_pyop_user_id.assert_called_once_with(
                str(mock_auth_session.id), "alice@example.com@showcase-person"
            )

    @pytest.mark.asyncio
    async def test_local_user_id_updated_to_presentation_sub(self):
        """Test that local user_id variable is updated to presentation_sub for claims storage."""
        with patch("api.routers.oidc.AuthSessionCRUD") as mock_crud_class, patch(
            "api.routers.oidc.VerificationConfigCRUD"
        ) as mock_ver_crud_class, patch(
            "api.routers.oidc.provider"
        ) as mock_provider, patch(
            "api.routers.oidc.Token"
        ) as mock_token_class, patch(
            "api.routers.oidc.settings"
        ) as mock_settings, patch(
            "api.routers.oidc.store_subject_identifier"
        ) as mock_store_subject:
            # Setup
            mock_settings.USE_REDIS_ADAPTER = True
            mock_settings.ACAPY_PROOF_FORMAT = "anoncreds"

            mock_auth_session = MagicMock(spec=AuthSession)
            mock_auth_session.id = ObjectId()
            mock_auth_session.pyop_user_id = "original-uuid-12345"
            mock_auth_session.pyop_auth_code = "test-code"
            mock_auth_session.ver_config_id = "test-config"
            mock_auth_session.request_parameters = {
                "pres_req_conf_id": "showcase-person",
                "nonce": "test-nonce",
            }
            mock_auth_session.presentation_exchange = {
                "pres_request": {
                    "anoncreds": {
                        "requested_attributes": {"req_attr_0": {"names": ["email"]}}
                    }
                },
                "pres": {
                    "anoncreds": {
                        "requested_proof": {
                            "revealed_attr_groups": {
                                "req_attr_0": {
                                    "values": {
                                        "email": {
                                            "raw": "alice@example.com",
                                            "encoded": "123",
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }

            mock_ver_config = MagicMock()
            mock_ver_config.subject_identifier = "email"
            mock_ver_config.generate_consistent_identifier = False

            presentation_sub = "alice@example.com@showcase-person"
            mock_token_class.get_claims.return_value = {
                "sub": presentation_sub,
                "pres_req_conf_id": "showcase-person",
                "acr": "vc_authn",
                "nonce": "test-nonce",
                "vc_presented_attributes": '{"email": "alice@example.com"}',
            }

            mock_crud = MagicMock()
            mock_crud.get_by_pyop_auth_code = AsyncMock(return_value=mock_auth_session)
            mock_crud.update_pyop_user_id = AsyncMock(return_value=True)
            mock_crud_class.return_value = mock_crud

            mock_ver_crud = MagicMock()
            mock_ver_crud.get = AsyncMock(return_value=mock_ver_config)
            mock_ver_crud_class.return_value = mock_ver_crud

            mock_authz_codes = MagicMock()
            mock_authz_info = {"sub": "original-uuid-12345", "user_info": {}}
            mock_authz_codes.__getitem__ = MagicMock(return_value=mock_authz_info)
            mock_authz_codes.pack = MagicMock(return_value="new-packed-code")
            mock_provider.provider.authz_state.authorization_codes = mock_authz_codes

            # Mock userinfo with set_claims_for_user method
            mock_userinfo = MagicMock()
            mock_userinfo.set_claims_for_user = MagicMock()
            mock_provider.provider.userinfo = mock_userinfo

            mock_provider.provider.handle_token_request = MagicMock(
                return_value=MagicMock(to_dict=lambda: {"access_token": "test-token"})
            )

            # Mock request with async context manager for form()
            mock_request = MagicMock()
            mock_form = MagicMock()
            mock_form._dict = {
                "code": "test-code",
                "grant_type": "authorization_code",
            }
            # Mock form() as async context manager
            mock_form_context = AsyncMock()
            mock_form_context.__aenter__ = AsyncMock(return_value=mock_form)
            mock_form_context.__aexit__ = AsyncMock(return_value=None)
            mock_request.form = MagicMock(return_value=mock_form_context)

            mock_db = MagicMock()

            # Execute
            await post_token(mock_request, mock_db)

            # Verify store_subject_identifier was called with presentation_sub
            mock_store_subject.assert_called_once_with(
                presentation_sub, "public", presentation_sub
            )
