import unittest

from detector.modules.web_recon.domain import (
    normalize_target,
    DomainValidationError,
)


class TestNormalizeTarget(unittest.TestCase):

    def test_add_https_scheme(self):
        result = normalize_target("example.com")
        self.assertEqual(result, "https://example.com/")

    def test_preserve_http_scheme(self):
        result = normalize_target("http://example.com")
        self.assertEqual(result, "http://example.com/")

    def test_normalize_hostname(self):
        result = normalize_target("HTTPS://EXAMPLE.COM")
        self.assertEqual(result, "https://example.com/")

    def test_preserve_port_and_path(self):
        result = normalize_target("http://example.com:8080/test")
        self.assertEqual(result, "http://example.com:8080/test")

    def test_reject_empty_target(self):
        with self.assertRaises(DomainValidationError):
            normalize_target("")

    def test_reject_whitespace(self):
        with self.assertRaises(DomainValidationError):
            normalize_target("example .com")

    def test_reject_invalid_scheme(self):
        with self.assertRaises(DomainValidationError):
            normalize_target("ftp://example.com")

    def test_reject_credentials(self):
        with self.assertRaises(DomainValidationError):
            normalize_target("https://user:pass@example.com")


if __name__ == "__main__":
    unittest.main()
