import unittest

from detector.reporting.formatter import format_value


class TestReportingFormatter(unittest.TestCase):

    def test_format_simple_dictionary(self):
        data = {
            "target": "example.com",
            "status": "success",
        }

        result = format_value(data)

        self.assertIn("target: example.com", result)
        self.assertIn("status: success", result)

    def test_format_nested_dictionary(self):
        data = {
            "dns": {
                "A": ["192.0.2.1"],
            }
        }

        result = format_value(data)

        self.assertIn("dns:", result)
        self.assertIn("A:", result)
        self.assertIn("192.0.2.1", result)

    def test_format_list(self):
        data = ["item one", "item two"]

        result = format_value(data)

        self.assertIn("item one", result)
        self.assertIn("item two", result)

    def test_format_none(self):
        result = format_value(None)

        self.assertIn("N/A", result)

    def test_format_empty_dictionary(self):
        result = format_value({})

        self.assertIn("empty", result.lower())


if __name__ == "__main__":
    unittest.main()


class TestReporters(unittest.TestCase):

    def test_save_text_report(self):
        import tempfile
        from pathlib import Path
        from detector.reporting import save_text_report

        data = {
            "target": "https://example.com",
            "dns": {"A": ["192.0.2.1"]},
        }

        with tempfile.TemporaryDirectory() as directory:
            report = save_text_report(
                data,
                output_dir=directory,
                version="1.1.0",
            )

            content = Path(report).read_text(
                encoding="utf-8"
            )

            self.assertIn("DETECTOR REPORT", content)
            self.assertIn("https://example.com", content)
            self.assertIn("192.0.2.1", content)
            self.assertIn("version: 1.1.0", content)

    def test_save_json_report(self):
        import tempfile
        import json
        from pathlib import Path
        from detector.reporting import save_json_report

        data = {
            "target": "https://example.com",
            "dns": {"A": ["192.0.2.1"]},
        }

        with tempfile.TemporaryDirectory() as directory:
            report = save_json_report(
                data,
                output_dir=directory,
                version="1.1.0",
            )

            content = json.loads(
                Path(report).read_text(encoding="utf-8")
            )

            self.assertEqual(
                content["metadata"]["version"], "1.1.0"
            )
            self.assertEqual(
                content["results"]["dns"]["A"],
                ["192.0.2.1"],
            )
