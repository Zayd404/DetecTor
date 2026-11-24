import unittest
from unittest.mock import patch, MagicMock

from detector.modules.web_recon.technology import identify_technology


class TestIdentifyTechnology(unittest.TestCase):

    @patch("detector.modules.web_recon.technology.urlopen")
    def test_detect_server_header(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers = {
            "Server": "Python HTTP Server",
        }

        mock_urlopen.return_value.__enter__.return_value = response

        result = identify_technology("http://example.com")

        self.assertEqual(result["status"], 200)
        self.assertEqual(
            result["technologies"][0]["value"],
            "Python HTTP Server",
        )

    @patch("detector.modules.web_recon.technology.urlopen")
    def test_detect_x_powered_by(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers = {
            "X-Powered-By": "PHP",
        }

        mock_urlopen.return_value.__enter__.return_value = response

        result = identify_technology("http://example.com")

        self.assertEqual(
            result["technologies"][0]["value"],
            "PHP",
        )

    @patch("detector.modules.web_recon.technology.urlopen")
    def test_no_technology_headers(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers = {}

        mock_urlopen.return_value.__enter__.return_value = response

        result = identify_technology("http://example.com")

        self.assertEqual(result["technologies"], [])
    @patch("detector.modules.web_recon.technology.urlopen")
    def test_detect_allowed_methods(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers = {
            "Allow": "GET, HEAD, OPTIONS",
        }

        mock_urlopen.return_value.__enter__.return_value = response

        result = identify_technology("http://example.com")

        self.assertEqual(
            result["allowed_methods"],
            ["GET", "HEAD", "OPTIONS"],
        )

    @patch("detector.modules.web_recon.technology.urlopen")
    def test_no_allowed_methods(self, mock_urlopen):
        response = MagicMock()
        response.status = 200
        response.headers = {}

        mock_urlopen.return_value.__enter__.return_value = response

        result = identify_technology("http://example.com")

        self.assertEqual(result["allowed_methods"], [])

if __name__ == "__main__":
    unittest.main()
