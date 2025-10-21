import pytest
from unittest.mock import patch, MagicMock
from api.core.logger_util import log_debug


class TestLogDebugDecorator:
    """Test log_debug decorator functionality."""

    @patch("api.core.logger_util.structlog.getLogger")
    @patch("api.core.logger_util.time.time")
    def test_log_debug_decorator_logs_function_call(self, mock_time, mock_get_logger):
        """Test that log_debug decorator logs function entry, exit, and timing."""
        # Setup mock logger
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        # Setup mock time
        mock_time.side_effect = [100.0, 100.5]  # Start and end times

        # Create a test function with the decorator
        @log_debug
        def test_function(x, y):
            return x + y

        # Call the decorated function
        result = test_function(5, 3)

        # Verify result is correct
        assert result == 8

        # Verify logger was created with function name
        mock_get_logger.assert_called_once_with("test_function")

        # Verify debug logs were called
        assert mock_logger.debug.call_count == 4

        # Verify log messages
        calls = [call[0][0] for call in mock_logger.debug.call_args_list]
        assert " >>>> test_function" in calls[0]
        assert "..with params" in calls[1]
        assert " <<<< test_function" in calls[2]
        assert "0.500 seconds" in calls[2]
        assert "..with ret_val" in calls[3]

    @patch("api.core.logger_util.structlog.getLogger")
    def test_log_debug_decorator_preserves_function_behavior(self, mock_get_logger):
        """Test that decorator preserves original function behavior."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        @log_debug
        def multiply(a, b):
            return a * b

        result = multiply(4, 7)
        assert result == 28

    @patch("api.core.logger_util.structlog.getLogger")
    def test_log_debug_decorator_with_keyword_args(self, mock_get_logger):
        """Test decorator works with keyword arguments."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        @log_debug
        def greet(name, greeting="Hello"):
            return f"{greeting}, {name}!"

        result = greet("Alice", greeting="Hi")
        assert result == "Hi, Alice!"

        # Verify logger was called
        mock_get_logger.assert_called_once_with("greet")

    @patch("api.core.logger_util.structlog.getLogger")
    def test_log_debug_decorator_with_no_args(self, mock_get_logger):
        """Test decorator works with functions that take no arguments."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        @log_debug
        def get_constant():
            return 42

        result = get_constant()
        assert result == 42

        # Verify logger was called
        mock_get_logger.assert_called_once_with("get_constant")
        assert mock_logger.debug.call_count == 4
