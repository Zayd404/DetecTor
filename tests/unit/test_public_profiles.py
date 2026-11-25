import unittest
from unittest.mock import patch

from detector.modules.people_osint.public_profiles import (
    generate_profile_links
)


class TestGenerateProfileLinks(unittest.TestCase):

    @patch(
        "detector.modules.people_osint.public_profiles._probe_url_raw",
        return_value=(404, "")
    )
    def test_valid_username(self, mock_probe):
        result = generate_profile_links("anonymous_123")
        self.assertTrue(result["valid"])

    @patch(
        "detector.modules.people_osint.public_profiles._probe_url_raw",
        return_value=(404, "")
    )
    def test_profile_platforms(self, mock_probe):
        result = generate_profile_links("anonymous_123")

        self.assertIn("GitHub", result["profiles"])
        self.assertIn("Instagram", result["profiles"])
        self.assertIn("TikTok", result["profiles"])
        self.assertIn("X", result["profiles"])
        self.assertIn("Reddit", result["profiles"])

    @patch(
        "detector.modules.people_osint.public_profiles._probe_url_raw",
        return_value=(404, "")
    )
    def test_github_url(self, mock_probe):
        result = generate_profile_links("anonymous_123")
        github = result["profiles"]["GitHub"]

        self.assertEqual(
            github["url"],
            "https://github.com/anonymous_123"
        )
        self.assertEqual(github["status"], "NOT FOUND")

    @patch(
        "detector.modules.people_osint.public_profiles._probe_url_raw"
    )
    def test_invalid_username(self, mock_probe):
        result = generate_profile_links("user name!")

        self.assertFalse(result["valid"])
        self.assertEqual(result["profiles"], {})
        mock_probe.assert_not_called()

    @patch(
        "detector.modules.people_osint.public_profiles._probe_url_raw"
    )
    def test_empty_username(self, mock_probe):
        result = generate_profile_links("")

        self.assertFalse(result["valid"])
        self.assertEqual(result["profiles"], {})
        mock_probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
