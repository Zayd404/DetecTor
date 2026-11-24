import unittest
import ssl
from unittest.mock import patch, MagicMock

from detector.modules.web_recon.ssl import inspect_ssl


class TestInspectSSL(unittest.TestCase):

    @patch("detector.modules.web_recon.ssl.ssl.create_default_context")
    @patch("detector.modules.web_recon.ssl.socket.create_connection")
    def test_ssl_inspection_success(self, mock_connect, mock_context):
        connection = MagicMock()
        connection.__enter__.return_value = connection

        secure_socket = MagicMock()
        secure_socket.version.return_value = "TLSv1.3"
        secure_socket.getpeercert.return_value = {
            "issuer": (("organizationName", "Test CA"),),
            "subject": (("commonName", "example.com"),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
        }

        secure_context = MagicMock()
        secure_context.__enter__.return_value = secure_socket

        mock_context.return_value.wrap_socket.return_value = secure_context
        mock_connect.return_value = connection

        result = inspect_ssl("https://example.com")

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["tls_version"], "TLSv1.3")
        self.assertEqual(result["issuer"], secure_socket.getpeercert.return_value["issuer"])
        self.assertEqual(result["subject"], secure_socket.getpeercert.return_value["subject"])

    @patch(
        "detector.modules.web_recon.ssl.socket.create_connection",
        side_effect=OSError("Connection failed"),
    )
    def test_connection_error(self, mock_connect):
        result = inspect_ssl("https://example.com")

        self.assertIn("error", result)
        self.assertEqual(result["domain"], "example.com")

    @patch("detector.modules.web_recon.ssl.ssl.create_default_context")
    @patch("detector.modules.web_recon.ssl.socket.create_connection")
    def test_ssl_error(self, mock_connect, mock_context):
        connection = MagicMock()
        connection.__enter__.return_value = connection

        mock_context.return_value.wrap_socket.side_effect = ssl.SSLError(
            "TLS failed"
        )
        mock_connect.return_value = connection

        result = inspect_ssl("https://example.com")

        self.assertIn("error", result)
        self.assertEqual(result["domain"], "example.com")


    @patch(
        "detector.modules.web_recon.ssl.socket.create_connection",
        side_effect=OSError("Connection test"),
    )
    def test_custom_https_port(self, mock_connect):
        inspect_ssl("https://example.com:8443")

        mock_connect.assert_called_once_with(
            ("example.com", 8443),
            timeout=15,
        )


    def test_tls_version_grading(self):
        from detector.modules.web_recon.ssl import analyze_tls_version

        self.assertEqual(analyze_tls_version("TLSv1.3"), "GOOD")
        self.assertEqual(analyze_tls_version("TLSv1.2"), "ACCEPTABLE")
        self.assertEqual(analyze_tls_version("TLSv1.1"), "OUTDATED")
        self.assertEqual(analyze_tls_version("TLSv1"), "OUTDATED")
        self.assertEqual(analyze_tls_version(None), "UNKNOWN")


    @patch("detector.modules.web_recon.ssl.ssl.create_default_context")
    @patch("detector.modules.web_recon.ssl.socket.create_connection")
    def test_ssl_inspection_includes_tls_grade(self, mock_connect, mock_context):
        connection = MagicMock()
        connection.__enter__.return_value = connection

        secure_socket = MagicMock()
        secure_socket.version.return_value = "TLSv1.3"
        secure_socket.getpeercert.return_value = {}

        secure_context = MagicMock()
        secure_context.__enter__.return_value = secure_socket

        mock_context.return_value.wrap_socket.return_value = secure_context
        mock_connect.return_value = connection

        result = inspect_ssl("https://example.com")

        self.assertEqual(result["tls_version"], "TLSv1.3")
        self.assertEqual(result["tls_grade"], "GOOD")


    @patch("detector.modules.web_recon.ssl.time.time")
    def test_certificate_validity_grading(self, mock_time):
        from detector.modules.web_recon.ssl import (
            analyze_certificate_validity,
        )

        mock_time.return_value = ssl.cert_time_to_seconds(
            "Jun  1 00:00:00 2026 GMT"
        )

        self.assertEqual(
            analyze_certificate_validity(
                "Jan  1 00:00:00 2026 GMT",
                "Dec  1 00:00:00 2026 GMT",
            ),
            "VALID",
        )

        self.assertEqual(
            analyze_certificate_validity(
                "Jan  1 00:00:00 2026 GMT",
                "Jun 20 00:00:00 2026 GMT",
            ),
            "EXPIRING_SOON",
        )

        self.assertEqual(
            analyze_certificate_validity(
                "Jan  1 00:00:00 2026 GMT",
                "May  1 00:00:00 2026 GMT",
            ),
            "EXPIRED",
        )

        self.assertEqual(
            analyze_certificate_validity(
                "Jul  1 00:00:00 2026 GMT",
                "Dec  1 00:00:00 2026 GMT",
            ),
            "NOT_YET_VALID",
        )

        self.assertEqual(
            analyze_certificate_validity(None, None),
            "UNKNOWN",
        )


    @patch("detector.modules.web_recon.ssl.time.time")
    @patch("detector.modules.web_recon.ssl.ssl.create_default_context")
    @patch("detector.modules.web_recon.ssl.socket.create_connection")
    def test_ssl_inspection_includes_certificate_grade(
        self, mock_connect, mock_context, mock_time
    ):
        mock_time.return_value = ssl.cert_time_to_seconds(
            "Jun  1 00:00:00 2026 GMT"
        )

        connection = MagicMock()
        connection.__enter__.return_value = connection

        secure_socket = MagicMock()
        secure_socket.version.return_value = "TLSv1.3"
        secure_socket.getpeercert.return_value = {
            "issuer": (),
            "subject": (),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec  1 00:00:00 2026 GMT",
        }

        secure_context = MagicMock()
        secure_context.__enter__.return_value = secure_socket

        mock_context.return_value.wrap_socket.return_value = secure_context
        mock_connect.return_value = connection

        result = inspect_ssl("https://example.com")

        self.assertEqual(result["certificate_grade"], "VALID")
        self.assertEqual(
            result["valid_from"],
            "Jan  1 00:00:00 2026 GMT",
        )
        self.assertEqual(
            result["valid_until"],
            "Dec  1 00:00:00 2026 GMT",
        )


    @patch("detector.modules.web_recon.ssl.time.time")
    def test_certificate_days_remaining(self, mock_time):
        from detector.modules.web_recon.ssl import (
            get_certificate_days_remaining,
        )

        mock_time.return_value = ssl.cert_time_to_seconds(
            "Jun  1 00:00:00 2026 GMT"
        )

        self.assertEqual(
            get_certificate_days_remaining(
                "Jun 20 00:00:00 2026 GMT"
            ),
            19,
        )

        self.assertEqual(
            get_certificate_days_remaining(
                "May 30 00:00:00 2026 GMT"
            ),
            -2,
        )

        self.assertIsNone(
            get_certificate_days_remaining(None)
        )

        self.assertIsNone(
            get_certificate_days_remaining("invalid-date")
        )


    @patch("detector.modules.web_recon.ssl.get_certificate_days_remaining")
    @patch("detector.modules.web_recon.ssl.socket.create_connection")
    @patch("detector.modules.web_recon.ssl.ssl.create_default_context")
    def test_ssl_inspection_includes_days_remaining(
        self, mock_context, mock_connect, mock_days
    ):
        mock_days.return_value = 183

        mock_socket = MagicMock()
        mock_secure_socket = MagicMock()

        mock_connect.return_value.__enter__.return_value = mock_socket
        mock_context.return_value.wrap_socket.return_value.__enter__.return_value = mock_secure_socket

        mock_secure_socket.getpeercert.return_value = {
            "notBefore": "Jan 1 00:00:00 2026 GMT",
            "notAfter": "Dec 1 00:00:00 2026 GMT",
        }
        mock_secure_socket.version.return_value = "TLSv1.3"

        result = inspect_ssl("https://example.com")

        self.assertEqual(result["days_remaining"], 183)
        mock_days.assert_called_once_with("Dec 1 00:00:00 2026 GMT")


if __name__ == "__main__":
    unittest.main()
