import unittest
from io import StringIO

from rich.console import Console

from detector.ui.reporter import render_web_report


class TestWebReporter(unittest.TestCase):

    def setUp(self):
        self.output = StringIO()
        self.console = Console(
            file=self.output,
            force_terminal=False,
            color_system=None,
        )

    def test_render_target(self):
        render_web_report(
            {"target": "https://example.com"},
            console=self.console,
        )

        self.assertIn("example.com", self.output.getvalue())

    def test_render_invalid_target_values(self):
        for target in ("", None, 123):
            with self.subTest(target=target):
                render_web_report(
                    {"target": target},
                    console=self.console,
                )

                output = self.output.getvalue()
                self.assertIn("DETECTOR WEB RECON", output)

                self.output.seek(0)
                self.output.truncate(0)


    def test_render_dns_records(self):
        results = {
            "target": "https://example.com",
            "dns": {
                "domain": "example.com",
                "ipv4": ["192.0.2.1"],
                "ipv6": ["2001:db8::1"],
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()
        self.assertIn("192.0.2.1", output)
        self.assertIn("2001:db8::1", output)

    def test_render_security_headers(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "status": 200,
                "security_analysis": {
                    "headers": {
                        "strict-transport-security": {
                            "status": "PRESENT",
                            "recommendation": None,
                        },
                        "content-security-policy": {
                            "status": "MISSING",
                            "recommendation": "Configure CSP.",
                        },
                    },
                    "summary": {
                        "present": 1,
                        "missing": 1,
                        "not_applicable": 0,
                        "invalid": 0,
                    },
                },
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()
        self.assertIn("PRESENT", output)
        self.assertIn("MISSING", output)

    def test_render_technology(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": [
                    {"source": "Server", "value": "Nginx"},
                ],
                "allowed_methods": ["GET", "HEAD"],
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()
        self.assertIn("Nginx", output)
        self.assertIn("GET", output)

    def test_render_ssl(self):
        results = {
            "target": "https://example.com",
            "ssl": {
                "tls_version": "TLSv1.3",
                "tls_grade": "GOOD",
                "certificate_grade": "VALID",
                "days_remaining": 120,
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()
        self.assertIn("TLSv1.3", output)
        self.assertIn("VALID", output)


    def test_render_invalid_ssl_days_remaining(self):
        results = {
            "target": "https://example.com",
            "ssl": {
                "tls_version": "TLSv1.3",
                "days_remaining": "one hundred twenty",
            },
        }

        render_web_report(results, console=self.console)
        output = self.output.getvalue()

        self.assertIn("SSL / TLS INSPECTION", output)
        self.assertIn("Days Remaining", output)
        self.assertNotIn("one hundred twenty", output)


    def test_render_invalid_ssl_tls_version(self):
        results = {
            "target": "https://example.com",
            "ssl": {
                "tls_version": {"unexpected": "value"},
            },
        }

        render_web_report(results, console=self.console)
        output = self.output.getvalue()

        self.assertIn("TLS Version", output)
        self.assertNotIn("unexpected", output)


    def test_render_ssl_grades_as_plain_text(self):
        tls_grade = "[bold red]FAKE TLS GRADE[/bold red]"
        certificate_grade = "[bold red]FAKE CERTIFICATE GRADE[/bold red]"

        results = {
            "target": "https://example.com",
            "ssl": {
                "tls_grade": tls_grade,
                "certificate_grade": certificate_grade,
            },
        }

        render_web_report(results, console=self.console)
        output = self.output.getvalue()

        self.assertIn(tls_grade, output)
        self.assertIn(certificate_grade, output)


    def test_render_ssl_error_as_plain_text(self):
        error = "[bold red]FAKE SSL ERROR[/bold red]"

        results = {
            "target": "https://example.com",
            "ssl": {
                "error": error,
            },
        }

        render_web_report(results, console=self.console)
        output = self.output.getvalue()

        self.assertIn(error, output)


    def test_render_ssl_note_as_plain_text(self):
        note = "[bold red]FAKE SSL NOTE[/bold red]"

        results = {
            "target": "http://example.com",
            "ssl": {
                "note": note,
            },
        }

        render_web_report(results, console=self.console)
        output = self.output.getvalue()

        self.assertIn(note, output)


    def test_render_http_status_and_method(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "status": 200,
                "method": "HEAD",
            },
        }

        render_web_report(results, console=self.console)
        output = self.output.getvalue()

        self.assertIn("200", output)
        self.assertIn("HEAD", output)

    def test_render_ssl_http_note(self):
        results = {
            "target": "http://example.com",
            "ssl": {
                "note": "SSL inspection requires HTTPS.",
            },
        }

        render_web_report(results, console=self.console)
        output = self.output.getvalue()

        self.assertIn("SSL inspection requires HTTPS.", output)


    def test_render_invalid_security_analysis(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "security_analysis": None,
            },
        }

        render_web_report(results, console=self.console)
        self.assertIn("HTTP SECURITY HEADERS", self.output.getvalue())

    def test_render_invalid_technology_item(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": [None],
            },
        }

        render_web_report(results, console=self.console)
        self.assertIn("TECHNOLOGY DETECTION", self.output.getvalue())


    def test_render_invalid_header_detail(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "security_analysis": {
                    "headers": {
                        "strict-transport-security": None,
                    },
                },
            },
        }

        render_web_report(results, console=self.console)
        self.assertIn(
            "HTTP SECURITY HEADERS",
            self.output.getvalue(),
        )


    def test_render_non_dict_dns_data(self):
        for dns_data in (None, "invalid", ["192.0.2.1"]):
            with self.subTest(dns_data=dns_data):
                results = {
                    "target": "example.com",
                    "dns": dns_data,
                }

                render_web_report(results, console=self.console)

                output = self.output.getvalue()

                self.assertIn("Unavailable", output)
                self.output.seek(0)
                self.output.truncate(0)


    def test_render_missing_dns_keys(self):
        results = {
            "target": "example.com",
            "dns": {},
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertEqual(output.count("No records"), 2)


    def test_render_invalid_dns_records(self):
        results = {
            "target": "https://example.com",
            "dns": {
                "ipv4": None,
                "ipv6": "invalid-format",
            },
        }

        render_web_report(results, console=self.console)
        self.assertIn("DNS RECORDS", self.output.getvalue())


    def test_render_invalid_technology_collection(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": None,
                "allowed_methods": [],
            },
        }

        render_web_report(results, console=self.console)
        self.assertIn("TECHNOLOGY DETECTION", self.output.getvalue())


    def test_render_invalid_allowed_methods(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": [],
                "allowed_methods": None,
            },
        }

        render_web_report(results, console=self.console)
        self.assertIn("TECHNOLOGY DETECTION", self.output.getvalue())


    def test_render_invalid_allowed_methods_string(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": [],
                "allowed_methods": "GET",
            },
        }

        render_web_report(results, console=self.console)
        self.assertIn("TECHNOLOGY DETECTION", self.output.getvalue())


    def test_render_invalid_results_type(self):
        render_web_report(None, console=self.console)

        self.assertIn(
            "DETECTOR WEB RECON",
            self.output.getvalue(),
        )


    def test_render_invalid_reports_collection(self):
        results = {
            "target": "https://example.com",
            "reports": ["report.json", "report.txt"],
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "DETECTOR WEB RECON",
            self.output.getvalue(),
        )


    def test_render_invalid_report_path(self):
        results = {
            "target": "https://example.com",
            "report": {
                "json": "report.json",
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "DETECTOR WEB RECON",
            self.output.getvalue(),
        )


    def test_render_invalid_report_file_value(self):
        results = {
            "target": "https://example.com",
            "reports": {
                "json": None,
                "text": 123,
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "REPORT FILES",
            self.output.getvalue(),
        )


    def test_render_invalid_header_summary(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "security_analysis": {
                    "headers": {},
                    "summary": "invalid-summary",
                },
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "HTTP SECURITY HEADERS",
            self.output.getvalue(),
        )


    def test_render_invalid_report_name(self):
        results = {
            "target": "https://example.com",
            "reports": {
                123: "report.json",
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "REPORT FILES",
            self.output.getvalue(),
        )


    def test_render_empty_report_names(self):
        results = {
            "target": "https://example.com",
            "reports": {
                "": "report.json",
                "   ": "report.txt",
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn("REPORT FILES", output)
        self.assertIn("report.json", output)
        self.assertIn("report.txt", output)


    def test_render_empty_fallback_report_path(self):
        for report in (None, ""):
            with self.subTest(report=report):
                results = {
                    "target": "https://example.com",
                    "reports": {},
                    "report": report,
                }

                render_web_report(results, console=self.console)

                output = self.output.getvalue()

                self.assertNotIn("Report saved:", output)

                self.output.seek(0)
                self.output.truncate(0)


    def test_render_report_path_as_plain_text(self):
        results = {
            "target": "https://example.com",
            "reports": {
                "json": "[bold red]ERROR[/bold red].json",
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn(
            "[bold red]ERROR[/bold red].json",
            output,
        )


    def test_render_fallback_report_path_as_plain_text(self):
        results = {
            "target": "https://example.com",
            "report": "[bold red]ERROR[/bold red].txt",
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn(
            "[bold red]ERROR[/bold red].txt",
            output,
        )


    def test_render_invalid_allowed_method_item(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": [],
                "allowed_methods": ["GET", 123],
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "TECHNOLOGY DETECTION",
            self.output.getvalue(),
        )


    def test_render_empty_allowed_method_item(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": [],
                "allowed_methods": ["GET", "", "   "],
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn("GET", output)
        self.assertIn("Invalid HTTP method data", output)


    def test_render_invalid_header_recommendation(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "security_analysis": {
                    "headers": {
                        "Content-Security-Policy": {
                            "status": "MISSING",
                            "recommendation": {
                                "unexpected": "data",
                            },
                        },
                    },
                },
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "HTTP SECURITY HEADERS",
            self.output.getvalue(),
        )


    def test_render_invalid_header_status(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "security_analysis": {
                    "headers": {
                        "Content-Security-Policy": {
                            "status": {
                                "unexpected": "data",
                            },
                            "recommendation": "Review policy",
                        },
                    },
                },
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "HTTP SECURITY HEADERS",
            self.output.getvalue(),
        )


    def test_render_unknown_header_status_as_plain_text(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "security_analysis": {
                    "headers": {
                        "Content-Security-Policy": {
                            "status": "[bold red]FAKE[/bold red]",
                            "recommendation": "Review policy",
                        },
                    },
                },
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "[bold red]FAKE[/bold red]",
            self.output.getvalue(),
        )


    def test_render_invalid_http_status_code(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "status": {
                    "unexpected": "data",
                },
                "security_analysis": {
                    "headers": {},
                },
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "HTTP SECURITY HEADERS",
            self.output.getvalue(),
        )


    def test_render_invalid_header_summary_values(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "security_analysis": {
                    "headers": {},
                    "summary": {
                        "present": "invalid",
                        "missing": [],
                        "invalid": True,
                        "not_applicable": {"value": 1},
                    },
                },
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "Header summary:",
            self.output.getvalue(),
        )


    def test_render_http_error_as_plain_text(self):
        results = {
            "target": "https://example.com",
            "headers": {
                "error": "[bold red]FAKE ERROR[/bold red]",
                "security_analysis": {
                    "headers": {},
                },
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn(
            "[bold red]FAKE ERROR[/bold red]",
            output,
        )


    def test_render_dns_error_as_plain_text(self):
        results = {
            "target": "example.com",
            "dns": {
                "ipv4": [],
                "ipv6": [],
                "error": "[bold red]FAKE DNS ERROR[/bold red]",
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn(
            "[bold red]FAKE DNS ERROR[/bold red]",
            output,
        )


    def test_render_invalid_dns_error_type(self):
        results = {
            "target": "example.com",
            "dns": {
                "ipv4": [],
                "ipv6": [],
                "error": {"message": "Fake DNS error"},
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertNotIn("Fake DNS error", output)
        self.assertIn("No records", output)


    def test_render_dns_record_family_mismatch(self):
        results = {
            "target": "example.com",
            "dns": {
                "ipv4": ["2001:db8::1"],
                "ipv6": ["192.0.2.1"],
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertEqual(output.count("Invalid DNS record"), 2)


    def test_render_empty_dns_record_as_invalid(self):
        results = {
            "target": "example.com",
            "dns": {
                "ipv4": ["", "   "],
                "ipv6": [],
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn("Invalid DNS record", output)


    def test_render_mixed_dns_records(self):
        results = {
            "target": "example.com",
            "dns": {
                "ipv4": ["192.0.2.1", "invalid-ip"],
                "ipv6": ["2001:db8::1", ""],
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn("192.0.2.1", output)
        self.assertIn("2001:db8::1", output)
        self.assertEqual(output.count("Invalid DNS record"), 2)


    def test_render_dns_string_collection(self):
        results = {
            "target": "example.com",
            "dns": {
                "ipv4": "",
                "ipv6": "",
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertEqual(output.count("Invalid DNS data"), 2)


    def test_render_invalid_dns_record_item(self):
        results = {
            "target": "example.com",
            "dns": {
                "ipv4": [{"unexpected": "data"}],
                "ipv6": [None],
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn("Invalid DNS record", output)


    def test_render_technology_values_as_plain_text(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": [
                    {
                        "source": "[bold red]FAKE SOURCE[/bold red]",
                        "value": "[bold red]FAKE VALUE[/bold red]",
                    }
                ],
            },
        }

        render_web_report(results, console=self.console)

        output = self.output.getvalue()

        self.assertIn(
            "[bold red]FAKE SOURCE[/bold red]",
            output,
        )
        self.assertIn(
            "[bold red]FAKE VALUE[/bold red]",
            output,
        )


    def test_render_http_methods_as_plain_text(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": [],
                "allowed_methods": [
                    "[bold red]FAKE METHOD[/bold red]",
                ],
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "[bold red]FAKE METHOD[/bold red]",
            self.output.getvalue(),
        )


    def test_render_technology_error_as_plain_text(self):
        results = {
            "target": "https://example.com",
            "technology": {
                "technologies": [],
                "error": "[bold red]FAKE TECHNOLOGY ERROR[/bold red]",
            },
        }

        render_web_report(results, console=self.console)

        self.assertIn(
            "[bold red]FAKE TECHNOLOGY ERROR[/bold red]",
            self.output.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
