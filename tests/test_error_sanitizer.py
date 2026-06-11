"""
Tests for _sanitize_error_message — written from behavioral specification only.
The implementation was NOT read before writing these tests.
"""
import unittest
import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import _sanitize_error_message


class TestSanitizeErrorMessage(unittest.TestCase):
    """Behavior-driven tests for _sanitize_error_message."""

    # ------------------------------------------------------------------
    # Spec example 1: empty string → generic fallback
    # ------------------------------------------------------------------
    def test_empty_string_returns_fallback(self):
        result = _sanitize_error_message("")
        self.assertEqual(
            result,
            "An internal processing error occurred.",
            "Empty input should return the generic fallback message.",
        )

    # ------------------------------------------------------------------
    # Spec example 2: whitespace-only → generic fallback
    # ------------------------------------------------------------------
    def test_whitespace_only_returns_fallback(self):
        result = _sanitize_error_message("   ")
        self.assertEqual(
            result,
            "An internal processing error occurred.",
            "Whitespace-only input should return the generic fallback message.",
        )

    # ------------------------------------------------------------------
    # Spec example 3: benign short error → passed through
    # ------------------------------------------------------------------
    def test_benign_short_error_passed_through(self):
        result = _sanitize_error_message("Connection reset by peer")
        self.assertEqual(
            result,
            "Connection reset by peer",
            "A short, benign error should be returned unchanged.",
        )

    # ------------------------------------------------------------------
    # Spec example 4: Python traceback → only final exception line
    # ------------------------------------------------------------------
    def test_traceback_strips_to_exception_line(self):
        traceback_input = (
            'Traceback (most recent call last):\n'
            '  File "/Users/dev/project/app.py", line 10, in <module>\n'
            '    raise ValueError("Bad URL")\n'
            'ValueError: Bad URL'
        )
        result = _sanitize_error_message(traceback_input)
        self.assertEqual(
            result,
            "ValueError: Bad URL",
            "A Python traceback should be stripped down to the final exception line.",
        )

    def test_multi_frame_traceback_with_indented_source_lines(self):
        """A multi-frame traceback with indented source-code lines before
        the final exception should skip frame headers and source snippets,
        returning only the last exception line."""
        multi_frame = (
            'Traceback (most recent call last):\n'
            '  File "/app/utils.py", line 42, in process\n'
            '    result = dangerous_call(url)\n'
            '  File "/app/scan.py", line 15, in dangerous_call\n'
            '    raise SecurityError("Untrusted input")\n'
            'SecurityError: Untrusted input'
        )
        result = _sanitize_error_message(multi_frame)
        self.assertEqual(
            result,
            "SecurityError: Untrusted input",
            "Should return the final exception line, skipping frame headers "
            "and indented source-code lines.",
        )

    # ------------------------------------------------------------------
    # Spec example 5: very long error → truncated with "..."
    # ------------------------------------------------------------------
    def test_long_error_truncated(self):
        long_input = "x" * 300
        result = _sanitize_error_message(long_input)
        self.assertLessEqual(
            len(result),
            200,
            "Result must not exceed 200 characters.",
        )
        self.assertTrue(
            result.endswith("..."),
            f"Truncated result must end with '...', got: {result!r}",
        )
        # Strengthened: verify the preserved prefix matches the original input.
        # The result should be <prefix of input> + "...", not a random string.
        prefix_len = len(result) - 3  # exclude the "..."
        self.assertGreater(
            prefix_len,
            0,
            "Truncated result should preserve at least one character of input.",
        )
        self.assertEqual(
            result[:prefix_len],
            long_input[:prefix_len],
            "The preserved prefix must match the beginning of the original input.",
        )

    # ------------------------------------------------------------------
    # Spec example 6: error with file paths → fallback
    # ------------------------------------------------------------------
    def test_error_with_file_paths_returns_fallback(self):
        input_with_path = (
            "Failed inside "
            "/Users/dev/project/.venv/lib/python3.12/site-packages/selenium/webdriver.py"
        )
        result = _sanitize_error_message(input_with_path)
        self.assertEqual(
            result,
            "An internal processing error occurred.",
            "Errors containing file paths should be replaced with the generic fallback.",
        )

    # ==================================================================
    # Edge-case category: empty / null-like inputs
    # ==================================================================

    def test_newlines_and_tabs_only_returns_fallback(self):
        """Category: empty/null inputs.
        Mixed whitespace (newlines + tabs) should also trigger the fallback."""
        result = _sanitize_error_message("\n\t  \n")
        self.assertEqual(
            result,
            "An internal processing error occurred.",
            "Mixed-whitespace-only input should return the generic fallback.",
        )

    # ==================================================================
    # Edge-case category: boundary values (truncation threshold)
    # ==================================================================

    def test_exactly_200_chars_should_not_truncate(self):
        """Category: boundary values.
        A message of exactly 200 characters should not be truncated,
        because the spec says 'no longer than 200 characters'."""
        input_200 = "y" * 200
        result = _sanitize_error_message(input_200)
        self.assertLessEqual(
            len(result),
            200,
            "Result must not exceed 200 characters.",
        )
        # If it's not a path/traceback, a 200-char message is just text.
        # It should not end with '...' unless it was truncated.
        self.assertFalse(
            result.endswith("..."),
            f"200-char input should not be truncated, got: {result!r}",
        )

    def test_201_chars_should_truncate(self):
        """Category: boundary values.
        A message of 201 characters crosses the threshold and should be truncated."""
        input_201 = "z" * 201
        result = _sanitize_error_message(input_201)
        self.assertLessEqual(
            len(result),
            200,
            "Result must not exceed 200 characters.",
        )
        self.assertTrue(
            result.endswith("..."),
            f"201-char input should be truncated, got: {result!r}",
        )
        # Strengthened: verify the preserved prefix matches the original input.
        prefix_len = len(result) - 3
        self.assertGreater(prefix_len, 0)
        self.assertEqual(
            result[:prefix_len],
            input_201[:prefix_len],
            "The preserved prefix must match the beginning of the original input.",
        )


if __name__ == "__main__":
    unittest.main()
