import unittest
from unittest.mock import patch

from detector.handlers.people_handler import (
    handle_username_search,
    handle_name_search,
)


class TestPeopleHandler(unittest.TestCase):

    @patch("detector.handlers.people_handler.show_username_result")
    @patch("detector.handlers.people_handler.generate_profile_links")
    @patch("builtins.input", return_value="testuser")
    def test_username_search(
        self, mock_input, mock_generate, mock_display
    ):
        mock_generate.return_value = {
            "valid": True,
            "username": "testuser",
            "profiles": {},
        }

        handle_username_search()

        mock_generate.assert_called_once_with("testuser")
        mock_display.assert_called_once()

    @patch("detector.handlers.people_handler.show_name_search_result")
    @patch("detector.handlers.people_handler.generate_search_links")
    @patch("builtins.input", return_value="test name")
    def test_name_search(
        self, mock_input, mock_generate, mock_display
    ):
        mock_generate.return_value = {
            "valid": True,
            "query": "test name",
            "search_links": {},
        }

        handle_name_search()

        mock_generate.assert_called_once_with("test name")
        mock_display.assert_called_once()


if __name__ == "__main__":
    unittest.main()
