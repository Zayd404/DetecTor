import unittest
from io import StringIO
from contextlib import redirect_stdout

from detector.ui.menus import (
    show_main_menu,
    show_people_menu,
    show_system_status,
)


class TestUIMenus(unittest.TestCase):

    def capture_output(self, function, *args):
        output = StringIO()

        with redirect_stdout(output):
            function(*args)

        return output.getvalue()

    def test_main_menu(self):
        output = self.capture_output(
            show_main_menu, "1.1.0"
        )

        self.assertIn("MAIN MENU", output)
        self.assertIn("Web & App Recon", output)
        self.assertIn("1.1.0", output)

    def test_people_menu(self):
        output = self.capture_output(show_people_menu)

        self.assertIn("PEOPLE OSINT", output)
        self.assertIn("Username Profile Search", output)
        self.assertIn("Public Name Search", output)

    def test_system_status(self):
        status = {
            "name": "DetecTor",
            "version": "1.1.0",
            "web_recon": True,
            "people_osint": True,
            "system": {
                "system": "Android",
                "platform": "Android",
                "machine": "aarch64",
                "python_version": "3.14.10",
                "executable": "/usr/bin/python",
            },
        }

        output = self.capture_output(
            show_system_status, status
        )

        self.assertIn("DetecTor", output)
        self.assertIn("SYSTEM STATUS", output)
        self.assertIn("Android", output)


if __name__ == "__main__":
    unittest.main()
