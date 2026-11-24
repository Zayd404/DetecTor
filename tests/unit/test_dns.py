import unittest
from unittest.mock import patch
import socket

from detector.modules.web_recon.dns import lookup_dns


class TestLookupDNS(unittest.TestCase):

    @patch("detector.modules.web_recon.dns.socket.getaddrinfo")
    def test_ipv4_resolution(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.0.2.10", 80))
        ]

        result = lookup_dns("example.com")

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["ipv4"], ["192.0.2.10"])
        self.assertEqual(result["ipv6"], [])

    @patch("detector.modules.web_recon.dns.socket.getaddrinfo")
    def test_ipv6_resolution(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "",
             ("2001:db8::10", 80, 0, 0))
        ]

        result = lookup_dns("example.com")

        self.assertEqual(result["ipv6"], ["2001:db8::10"])

    @patch("detector.modules.web_recon.dns.socket.getaddrinfo")
    def test_remove_duplicate_addresses(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.0.2.10", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.0.2.10", 80)),
        ]

        result = lookup_dns("example.com")

        self.assertEqual(result["ipv4"], ["192.0.2.10"])

    @patch("detector.modules.web_recon.dns.socket.getaddrinfo")
    def test_dns_error(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("DNS lookup failed")

        result = lookup_dns("example.com")

        self.assertEqual(result["ipv4"], [])
        self.assertEqual(result["ipv6"], [])
        self.assertIn("error", result)

    def test_invalid_target(self):
        with self.assertRaises(ValueError):
            lookup_dns("")


if __name__ == "__main__":
    unittest.main()
