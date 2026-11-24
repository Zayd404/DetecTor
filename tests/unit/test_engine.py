import unittest
from unittest.mock import patch

from detector.core.engine import DetecTorEngine


class TestDetecTorEngine(unittest.TestCase):

    def setUp(self):
        self.engine = DetecTorEngine()

    def test_web_recon_requires_authorization(self):
        with self.assertRaises(PermissionError):
            self.engine.web_recon(
                "http://127.0.0.1",
                authorized=False
            )
    @patch("detector.core.engine.save_text_report")
    @patch("detector.core.engine.save_json_report")
    @patch("detector.core.engine.inspect_ssl")
    @patch("detector.core.engine.identify_technology")
    @patch("detector.core.engine.inspect_headers")
    @patch("detector.core.engine.lookup_dns")
    def test_web_recon_with_authorization(
        self,
        mock_dns,
        mock_headers,
        mock_technology,
        mock_ssl,
        mock_report,
        mock_text_report
    ):
        mock_dns.return_value = {"ipv4": ["127.0.0.1"]}
        mock_headers.return_value = {"status": 200}
        mock_technology.return_value = {"technologies": []}
        mock_ssl.return_value = {"valid": True}
        mock_report.return_value = "reports/test.json"
        mock_text_report.return_value = "reports/test.txt"

        result = self.engine.web_recon(
            "https://127.0.0.1",
            authorized=True
        )

        self.assertIn("dns", result)
        self.assertIn("headers", result)
        self.assertIn("technology", result)
        self.assertIn("ssl", result)
        self.assertIn("report", result)
        self.assertIn("reports", result)

        mock_report.assert_called_once()
        mock_text_report.assert_called_once()

        self.assertEqual(
            result["reports"]["json"],
            "reports/test.json",
        )
        self.assertEqual(
            result["reports"]["txt"],
            "reports/test.txt",
        )

        self.assertEqual(
            mock_report.call_args.kwargs["version"],
            self.engine.version,
        )
        self.assertEqual(
            mock_text_report.call_args.kwargs["report_type"],
            "web_recon",
        )


if __name__ == "__main__":
    unittest.main()
