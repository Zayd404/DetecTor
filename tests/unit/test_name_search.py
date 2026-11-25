import unittest

from detector.modules.people_osint.name_search import (
    generate_search_links
)


class TestGenerateSearchLinks(unittest.TestCase):

    def test_valid_query(self):
        result = generate_search_links("DetecTor project")

        self.assertTrue(result["valid"])

    def test_search_engines(self):
        result = generate_search_links("DetecTor")

        expected_categories = (
            "General Web",
            "LinkedIn Profile",
            "Social Media",
            "Code & Git",
            "Documents (PDF/DOC)",
            "Paste & Leaks",
            "DuckDuckGo",
        )

        for category in expected_categories:
            self.assertIn(category, result["search_links"])

    def test_empty_query(self):
        result = generate_search_links("")

        self.assertFalse(result["valid"])

    def test_query_too_long(self):
        result = generate_search_links("a" * 101)

        self.assertFalse(result["valid"])

    def test_query_encoding(self):
        result = generate_search_links("DetecTor project")

        self.assertIn(
            "DetecTor+project",
            result["search_links"]["General Web"]
        )


if __name__ == "__main__":
    unittest.main()
