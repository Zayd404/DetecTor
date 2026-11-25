import unittest
from unittest.mock import patch, MagicMock

from detector.handlers.web_handler import handle_web_recon


class TestWebHandler(unittest.TestCase):

    @patch("builtins.input", side_effect=["", "yes"])
    def test_empty_target(self, mock_input):
        engine = MagicMock()

        with patch("builtins.print") as mock_print:
            handle_web_recon(engine)

        engine.web_recon.assert_not_called()
        self.assertTrue(mock_print.called)

    @patch("builtins.input", side_effect=["example.com", "no"])
    def test_without_permission(self, mock_input):
        engine = MagicMock()

        with patch("builtins.print"):
            handle_web_recon(engine)

        engine.web_recon.assert_not_called()

    @patch("builtins.input", side_effect=["example.com", "yes"])
    def test_authorized_recon(self, mock_input):
        engine = MagicMock()
        engine.web_recon.return_value = {
            "target": "https://example.com",
            "report": "reports/test.json",
        }

        with patch("builtins.print"):
            handle_web_recon(engine)

        engine.web_recon.assert_called_once_with(
            "example.com",
            authorized=True,
        )



    @patch("detector.handlers.web_handler.render_web_report")
    @patch("builtins.input", side_effect=["example.com", "yes"])
    def test_authorized_recon_renders_report(
        self, mock_input, mock_report
    ):
        engine = MagicMock()
        results = {
            "target": "https://example.com",
            "dns": {
                "ipv4": ["192.0.2.1"],
                "ipv6": [],
            },
        }
        engine.web_recon.return_value = results

        handle_web_recon(engine)

        engine.web_recon.assert_called_once_with(
            "example.com",
            authorized=True,
        )
        mock_report.assert_called_once_with(results)


if __name__ == "__main__":
    unittest.main()
