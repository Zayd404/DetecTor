import unittest

from detector.modules.people_osint.username import validate_username


class TestValidateUsername(unittest.TestCase):

    def test_valid_username(self):
        result = validate_username("anonymous_123")
        self.assertTrue(result["valid"])

    def test_empty_username(self):
        result = validate_username("")
        self.assertFalse(result["valid"])

    def test_username_too_short(self):
        result = validate_username("ab")
        self.assertFalse(result["valid"])

    def test_username_too_long(self):
        result = validate_username("a" * 31)
        self.assertFalse(result["valid"])

    def test_invalid_characters(self):
        result = validate_username("user name!")
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
