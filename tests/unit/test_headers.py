import unittest
from urllib.error import HTTPError
from unittest.mock import patch, MagicMock

from detector.modules.web_recon.headers import (
    inspect_headers,
    analyze_security_headers,
)


class TestInspectHeaders(unittest.TestCase):

    def test_http_hsts_not_applicable(self):
        result = analyze_security_headers({}, "http")

        self.assertEqual(
            result["headers"]["strict-transport-security"]["status"],
            "NOT_APPLICABLE",
        )

    def test_missing_headers_count(self):
        result = analyze_security_headers({}, "https")

        self.assertEqual(result["summary"]["missing"], 6)
        self.assertEqual(result["summary"]["present"], 0)

    @patch("detector.modules.web_recon.headers.urlopen")
    def test_security_headers_found(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers.items.return_value = [
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Frame-Options", "DENY"),
        ]

        mock_urlopen.return_value.__enter__.return_value = response

        result = inspect_headers("http://example.com")

        self.assertEqual(result["status"], 200)
        self.assertEqual(
            result["security_headers"]["content-security-policy"],
            "default-src 'self'",
        )

    @patch("detector.modules.web_recon.headers.urlopen")
    def test_head_method_success(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers.items.return_value = []

        mock_urlopen.return_value.__enter__.return_value = response

        result = inspect_headers("http://example.com")

        self.assertEqual(result["method"], "HEAD")
        mock_urlopen.assert_called_once()

    @patch("detector.modules.web_recon.headers.urlopen")
    def test_head_405_fallback_to_get(self, mock_urlopen):
        error = HTTPError(
            "http://example.com",
            405,
            "Method Not Allowed",
            {},
            None,
        )

        response = MagicMock()
        response.status = 200
        response.headers.items.return_value = []

        mock_urlopen.side_effect = [
            error,
            MagicMock(
                __enter__=MagicMock(return_value=response),
                __exit__=MagicMock(return_value=False),
            ),
        ]

        result = inspect_headers("http://example.com")

        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["status"], 200)
        self.assertEqual(mock_urlopen.call_count, 2)

    @patch("detector.modules.web_recon.headers.urlopen")
    def test_head_501_fallback_to_get(self, mock_urlopen):
        error = HTTPError(
            "http://example.com",
            501,
            "Not Implemented",
            {},
            None,
        )

        response = MagicMock()
        response.status = 200
        response.headers.items.return_value = []

        mock_urlopen.side_effect = [
            error,
            MagicMock(
                __enter__=MagicMock(return_value=response),
                __exit__=MagicMock(return_value=False),
            ),
        ]

        result = inspect_headers("http://example.com")

        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["status"], 200)
        self.assertEqual(mock_urlopen.call_count, 2)

    @patch("detector.modules.web_recon.headers.urlopen")
    def test_security_headers_missing(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers.items.return_value = []

        mock_urlopen.return_value.__enter__.return_value = response

        result = inspect_headers("http://example.com")

        for value in result["security_headers"].values():
            self.assertIsNone(value)

    def test_invalid_x_content_type_options(self):
        from detector.modules.web_recon.headers import analyze_security_headers

        headers = {
            "x-content-type-options": "invalid-value"
        }

        result = analyze_security_headers(headers, "https")

        self.assertEqual(
            result["headers"]["x-content-type-options"]["status"],
            "INVALID",
        )


    def test_invalid_headers_count(self):
        from detector.modules.web_recon.headers import analyze_security_headers

        headers = {
            "x-content-type-options": "invalid-value"
        }

        result = analyze_security_headers(headers, "https")

        self.assertEqual(result["summary"]["invalid"], 1)
        self.assertEqual(result["summary"]["present"], 0)


    def test_invalid_referrer_policy(self):
        from detector.modules.web_recon.headers import analyze_security_headers

        headers = {
            "referrer-policy": "invalid-policy"
        }

        result = analyze_security_headers(headers, "https")

        self.assertEqual(
            result["headers"]["referrer-policy"]["status"],
            "INVALID",
        )


    def test_invalid_empty_csp(self):
        result = analyze_security_headers(
            {"content-security-policy": "   "},
            "https",
        )

        self.assertEqual(
            result["headers"]["content-security-policy"]["status"],
            "INVALID",
        )


    def test_invalid_empty_permissions_policy(self):
        result = analyze_security_headers(
            {"permissions-policy": "   "},
            "https",
        )

        self.assertEqual(
            result["headers"]["permissions-policy"]["status"],
            "INVALID",
        )


    def test_invalid_hsts_max_age(self):
        result = analyze_security_headers(
            {"strict-transport-security": "max-age=-100"},
            "https",
        )

        self.assertEqual(
            result["headers"]["strict-transport-security"]["status"],
            "INVALID",
        )


if __name__ == "__main__":
    unittest.main()
