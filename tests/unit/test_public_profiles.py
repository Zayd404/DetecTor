import unittest

from detector.modules.people_osint.public_profiles import (
    generate_profile_links
)


class TestGenerateProfileLinks(unittest.TestCase):

    def test_valid_username(self):
        result = generate_profile_links("anonymous_123")
        self.assertTrue(result["valid"])

    def test_profile_platforms(self):
        result = generate_profile_links("anonymous_123")

        self.assertIn("GitHub", result["profiles"])
        self.assertIn("Instagram", result["profiles"])
        self.assertIn("TikTok", result["profiles"])
        self.assertIn("X", result["profiles"])
        self.assertIn("Reddit", result["profiles"])

    def test_github_url(self):
        result = generate_profile_links("anonymous_123")

        self.assertEqual(
            result["profiles"]["GitHub"],
            "https://github.com/anonymous_123"
        )

    def test_invalid_username(self):
        result = generate_profile_links("user name!")

        self.assertFalse(result["valid"])
        self.assertEqual(result["profiles"], {})

    def test_empty_username(self):
        result = generate_profile_links("")

        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
