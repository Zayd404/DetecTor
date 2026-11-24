import tomllib
from pathlib import Path


class ConfigError(Exception):
    """Configuration loading error."""


class Config:
    def __init__(self, data):
        self.data = data

    @classmethod
    def load(cls, path=None):
        if path is None:
            root = Path(__file__).resolve().parents[3]
            path = root / "config" / "settings.toml"
        else:
            path = Path(path)

        if not path.is_file():
            raise ConfigError(f"Config file not found: {path}")

        try:
            with path.open("rb") as file:
                data = tomllib.load(file)
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise ConfigError(f"Invalid configuration: {error}") from error

        required = ("app", "web_recon", "people_osint", "storage",
                    "reporting", "logging")

        for section in required:
            if section not in data:
                raise ConfigError(f"Missing section: {section}")

        if data["web_recon"].get("require_authorization") is not True:
            raise ConfigError("Web authorization must remain enabled.")

        if data["people_osint"].get("public_sources_only") is not True:
            raise ConfigError("People OSINT must use public sources only.")

        return cls(data)

    def get(self, section, key, default=None):
        return self.data.get(section, {}).get(key, default)
