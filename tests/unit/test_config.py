import unittest
import tempfile
from pathlib import Path

from detector.core.config import Config, ConfigError


VALID_CONFIG = """
[app]
name = "DetecTor"
version = "1.0.0"

[web_recon]
require_authorization = true

[people_osint]
public_sources_only = true

[storage]
database = "test.db"
cache_directory = "cache"

[reporting]
output_directory = "reports"

[logging]
level = "INFO"
output_directory = "logs"
"""


class TestConfig(unittest.TestCase):

    def load_config(self, content):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "settings.toml"
            path.write_text(content, encoding="utf-8")
            return Config.load(path)

    def test_valid_config(self):
        config = self.load_config(VALID_CONFIG)
        self.assertEqual(config.get("app", "name"), "DetecTor")

    def test_authorization_must_be_enabled(self):
        content = VALID_CONFIG.replace(
            "require_authorization = true",
            "require_authorization = false"
        )

        with self.assertRaises(ConfigError):
            self.load_config(content)

    def test_public_sources_only_must_be_enabled(self):
        content = VALID_CONFIG.replace(
            "public_sources_only = true",
            "public_sources_only = false"
        )

        with self.assertRaises(ConfigError):
            self.load_config(content)


if __name__ == "__main__":
    unittest.main()
