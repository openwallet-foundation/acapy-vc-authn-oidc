"""Tests for HTTP exception utilities."""

import pytest
from unittest.mock import patch
from pymongo.errors import WriteError
from fastapi import HTTPException
from fastapi import status as http_status

from api.core.http_exception_util import (
    raise_appropriate_http_exception,
    check_and_raise_not_found_http_exception,
    CONFLICT_DEFAULT_MSG,
    NOT_FOUND_DEFAULT_MSG,
    UNKNOWN_DEFAULT_MSG,
)


class TestRaiseAppropriateHttpException:
    """Test raise_appropriate_http_exception function."""

    def test_raise_appropriate_http_exception_duplicate_key_error(self):
        """Test handling of duplicate key error (code 11000)."""
        write_error = WriteError("Duplicate key error", code=11000, details={})

        with pytest.raises(HTTPException) as exc_info:
            raise_appropriate_http_exception(write_error)

        assert exc_info.value.status_code == http_status.HTTP_409_CONFLICT
        assert exc_info.value.detail == CONFLICT_DEFAULT_MSG

    def test_raise_appropriate_http_exception_duplicate_key_error_custom_message(self):
        """Test handling of duplicate key error with custom message."""
        write_error = WriteError("Duplicate key error", code=11000, details={})
        custom_message = "Custom conflict message"

        with pytest.raises(HTTPException) as exc_info:
            raise_appropriate_http_exception(write_error, custom_message)

        assert exc_info.value.status_code == http_status.HTTP_409_CONFLICT
        assert exc_info.value.detail == custom_message

    def test_raise_appropriate_http_exception_unknown_error(self):
        """Test handling of unknown error codes."""
        write_error = WriteError("Unknown error", code=12345, details={})

        with patch("api.core.http_exception_util.logger") as mock_logger:
            with pytest.raises(HTTPException) as exc_info:
                raise_appropriate_http_exception(write_error)

            assert (
                exc_info.value.status_code == http_status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            assert exc_info.value.detail == UNKNOWN_DEFAULT_MSG
            mock_logger.error.assert_called_once_with("Unknown error", err=write_error)

    def test_raise_appropriate_http_exception_unknown_error_custom_message(self):
        """Test handling of unknown error with custom exists message (should still use default for 500)."""
        write_error = WriteError("Unknown error", code=99999, details={})
        custom_message = "Custom conflict message"

        with patch("api.core.http_exception_util.logger") as mock_logger:
            with pytest.raises(HTTPException) as exc_info:
                raise_appropriate_http_exception(write_error, custom_message)

            # Should still use default message for 500 errors, not custom message
            assert (
                exc_info.value.status_code == http_status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            assert exc_info.value.detail == UNKNOWN_DEFAULT_MSG
            mock_logger.error.assert_called_once_with("Unknown error", err=write_error)

    def test_raise_appropriate_http_exception_zero_error_code(self):
        """Test handling of zero error code."""
        write_error = WriteError("Zero error code", code=0, details={})

        with patch("api.core.http_exception_util.logger") as mock_logger:
            with pytest.raises(HTTPException) as exc_info:
                raise_appropriate_http_exception(write_error)

            assert (
                exc_info.value.status_code == http_status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            assert exc_info.value.detail == UNKNOWN_DEFAULT_MSG
            mock_logger.error.assert_called_once_with("Unknown error", err=write_error)

    def test_raise_appropriate_http_exception_negative_error_code(self):
        """Test handling of negative error code."""
        write_error = WriteError("Negative error code", code=-1, details={})

        with patch("api.core.http_exception_util.logger") as mock_logger:
            with pytest.raises(HTTPException) as exc_info:
                raise_appropriate_http_exception(write_error)

            assert (
                exc_info.value.status_code == http_status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            assert exc_info.value.detail == UNKNOWN_DEFAULT_MSG
            mock_logger.error.assert_called_once_with("Unknown error", err=write_error)


class TestCheckAndRaiseNotFoundHttpException:
    """Test check_and_raise_not_found_http_exception function."""

    def test_check_and_raise_not_found_http_exception_none_response(self):
        """Test raising not found exception when response is None."""
        with pytest.raises(HTTPException) as exc_info:
            check_and_raise_not_found_http_exception(None)

        assert exc_info.value.status_code == http_status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == NOT_FOUND_DEFAULT_MSG

    def test_check_and_raise_not_found_http_exception_none_response_custom_message(
        self,
    ):
        """Test raising not found exception with custom message."""
        custom_message = "Custom not found message"

        with pytest.raises(HTTPException) as exc_info:
            check_and_raise_not_found_http_exception(None, custom_message)

        assert exc_info.value.status_code == http_status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == custom_message

    def test_check_and_raise_not_found_http_exception_valid_response(self):
        """Test that no exception is raised for valid response."""
        valid_response = {"id": "123", "name": "test"}

        # Should not raise any exception
        try:
            check_and_raise_not_found_http_exception(valid_response)
        except HTTPException:
            pytest.fail("HTTPException was raised for valid response")

    def test_check_and_raise_not_found_http_exception_empty_dict(self):
        """Test that empty dict is considered valid (not None)."""
        empty_dict = {}

        # Should not raise any exception
        try:
            check_and_raise_not_found_http_exception(empty_dict)
        except HTTPException:
            pytest.fail("HTTPException was raised for empty dict")

    def test_check_and_raise_not_found_http_exception_empty_list(self):
        """Test that empty list is considered valid (not None)."""
        empty_list = []

        # Should not raise any exception
        try:
            check_and_raise_not_found_http_exception(empty_list)
        except HTTPException:
            pytest.fail("HTTPException was raised for empty list")

    def test_check_and_raise_not_found_http_exception_zero_value(self):
        """Test that zero value is considered valid (not None)."""
        zero_value = 0

        # Should not raise any exception
        try:
            check_and_raise_not_found_http_exception(zero_value)
        except HTTPException:
            pytest.fail("HTTPException was raised for zero value")

    def test_check_and_raise_not_found_http_exception_false_value(self):
        """Test that False value is considered valid (not None)."""
        false_value = False

        # Should not raise any exception
        try:
            check_and_raise_not_found_http_exception(false_value)
        except HTTPException:
            pytest.fail("HTTPException was raised for False value")

    def test_check_and_raise_not_found_http_exception_empty_string(self):
        """Test that empty string is considered valid (not None)."""
        empty_string = ""

        # Should not raise any exception
        try:
            check_and_raise_not_found_http_exception(empty_string)
        except HTTPException:
            pytest.fail("HTTPException was raised for empty string")


class TestConstants:
    """Test that constants are properly defined."""

    def test_conflict_default_msg_is_string(self):
        """Test that CONFLICT_DEFAULT_MSG is a non-empty string."""
        assert isinstance(CONFLICT_DEFAULT_MSG, str)
        assert len(CONFLICT_DEFAULT_MSG) > 0
        assert CONFLICT_DEFAULT_MSG == "The requested resource already exists"

    def test_not_found_default_msg_is_string(self):
        """Test that NOT_FOUND_DEFAULT_MSG is a non-empty string."""
        assert isinstance(NOT_FOUND_DEFAULT_MSG, str)
        assert len(NOT_FOUND_DEFAULT_MSG) > 0
        assert NOT_FOUND_DEFAULT_MSG == "The requested resource wasn't found"

    def test_unknown_default_msg_is_string(self):
        """Test that UNKNOWN_DEFAULT_MSG is a non-empty string."""
        assert isinstance(UNKNOWN_DEFAULT_MSG, str)
        assert len(UNKNOWN_DEFAULT_MSG) > 0
        assert UNKNOWN_DEFAULT_MSG == "The server was unable to process the request"


class TestWriteErrorIntegration:
    """Test integration with actual WriteError objects."""

    def test_write_error_with_details(self):
        """Test WriteError with details dictionary."""
        details = {"index": 0, "code": 11000, "errmsg": "duplicate key"}
        write_error = WriteError("Duplicate key error", code=11000, details=details)

        with pytest.raises(HTTPException) as exc_info:
            raise_appropriate_http_exception(write_error)

        assert exc_info.value.status_code == http_status.HTTP_409_CONFLICT
        assert exc_info.value.detail == CONFLICT_DEFAULT_MSG

    def test_write_error_without_details(self):
        """Test WriteError without details dictionary."""
        write_error = WriteError("Error without details", code=11000, details=None)

        with pytest.raises(HTTPException) as exc_info:
            raise_appropriate_http_exception(write_error)

        assert exc_info.value.status_code == http_status.HTTP_409_CONFLICT
        assert exc_info.value.detail == CONFLICT_DEFAULT_MSG

    def test_write_error_code_as_string(self):
        """Test WriteError with code as string (should still work)."""
        write_error = WriteError("String code error", code="11000", details={})

        # This should trigger the else branch since "11000" != 11000
        with patch("api.core.http_exception_util.logger") as mock_logger:
            with pytest.raises(HTTPException) as exc_info:
                raise_appropriate_http_exception(write_error)

            assert (
                exc_info.value.status_code == http_status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            assert exc_info.value.detail == UNKNOWN_DEFAULT_MSG
            mock_logger.error.assert_called_once_with("Unknown error", err=write_error)
